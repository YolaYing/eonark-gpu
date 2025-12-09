package bls12_381_gpu

import (
	"log"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_bls12_381 "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381"
	icicle_msm "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381/msm"
	icicle_ntt "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381/ntt"
	icicle_vecops "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381/vecOps"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

func blsProjectiveToGnarkAffine(p icicle_bls12_381.Projective) curve.G1Affine {
	bx := p.X.ToBytesLittleEndian()
	by := p.Y.ToBytesLittleEndian()
	bz := p.Z.ToBytesLittleEndian()

	var ax, ay, az fp.Element
	ax, _ = fp.LittleEndian.Element((*[fp.Bytes]byte)(bx))
	ay, _ = fp.LittleEndian.Element((*[fp.Bytes]byte)(by))
	az, _ = fp.LittleEndian.Element((*[fp.Bytes]byte)(bz))

	var zInv fp.Element
	zInv.Inverse(&az)
	ax.Mul(&ax, &zInv)
	ay.Mul(&ay, &zInv)

	return curve.G1Affine{X: ax, Y: ay}
}

// OnDeviceCommit 使用已在 GPU 的 G1 (SRS) 做 MSM： [p]·G1
// p: 多项式系数（假设是 Montgomery 形式；gnark-crypto/fr 默认就是）
// G1Device: 已在设备端的 G1 bases（例如 pk.deviceInfo.G1Device.G1）
// 返回：kzg.Digest (= curve.G1Affine)
func OnDeviceCommit(p []fr.Element, G1Device icicle_core.DeviceSlice) (kzg.Digest, icicle_runtime.EIcicleError) {
	// 1) 把标量拷到设备
	host := icicle_core.HostSliceFromElements(p)

	var scalarsDev icicle_core.DeviceSlice
	host.CopyToDevice(&scalarsDev, true)
	defer scalarsDev.Free()

	// 2) 配置 MSM
	cfg := icicle_msm.GetDefaultMSMConfig()
	// gnark-crypto 的标量/基点默认在 Montgomery 形式
	cfg.AreScalarsMontgomeryForm = true
	cfg.AreBasesMontgomeryForm = false
	cfg.PrecomputeFactor = 1 // not using precompute

	// 3) 运行 MSM（输出 1 个 projective 点）
	out := make(icicle_core.HostSlice[icicle_bls12_381.Projective], 1)
	st := icicle_msm.Msm(scalarsDev, G1Device, &cfg, out)

	// 4) 转成 gnark 的 Affine（= kzg.Digest）
	res := blsProjectiveToGnarkAffine(out[0])

	// 5) 清理设备内存
	if st != icicle_runtime.Success {
		return kzg.Digest{}, st
	}

	return kzg.Digest(res), icicle_runtime.Success
}

// OnDeviceCommitBatchLRO 在 GPU 上对多条多项式（同一套 G1Lagrange 基点）做 batch MSM。
// 典型用法：一次性对 L/R/O 三个多项式做 KZG commit。
// 要求：
//   - polys 长度 = batchSize（例如 3）
//   - 每个 polys[i] 都是长度相同的 []fr.Element（例如 N = domain0.Cardinality）
//   - G1Lagrange 是长度 >= N 的 DeviceSlice（例如 pk.deviceInfo.G1Device.G1Lagrange.RangeTo(N, false)）
func OnDeviceCommitBatchLRO(
	polys [][]fr.Element,
	G1Lagrange icicle_core.DeviceSlice,
) ([]kzg.Digest, icicle_runtime.EIcicleError) {

	batchSize := len(polys)
	if batchSize == 0 {
		return nil, icicle_runtime.Success
	}

	// 确认所有多项式长度一致
	N := len(polys[0])
	for i := 1; i < batchSize; i++ {
		if len(polys[i]) != N {
			// EIcicleError 是 int 枚举，不能用 struct literal
			// 这里直接返回 InvalidArgument + 日志说明原因
			log.Printf("[OnDeviceCommitBatchLRO] polys have different lengths: N=%d, len(polys[%d])=%d",
				N, i, len(polys[i]))
			return nil, icicle_runtime.InvalidArgument
		}
	}

	// 1) 把 [L, R, O] flatten 成一个大标量数组：L || R || O
	flatten := make([]fr.Element, 0, batchSize*N)
	for i := 0; i < batchSize; i++ {
		flatten = append(flatten, polys[i]...)
	}

	// 2) HostSlice → DeviceSlice
	host := icicle_core.HostSliceFromElements(flatten)
	var scalarsDev icicle_core.DeviceSlice
	host.CopyToDevice(&scalarsDev, true)
	defer scalarsDev.Free()

	// 3) MSMConfig：开启 batch + 共享 bases
	cfg := icicle_msm.GetDefaultMSMConfig()
	cfg.BatchSize = int32(batchSize)
	cfg.ArePointsSharedInBatch = true
	cfg.AreScalarsMontgomeryForm = true // 跟你现有 OnDeviceCommit 保持一致
	cfg.AreBasesMontgomeryForm = false  // G1Lagrange 是非 Montgomery
	cfg.PrecomputeFactor = 1

	log.Printf("[MSM batch] size=%d, BatchSize=%d, PrecomputeFactor=%d, C=%d, Bitsize=%d",
		N, cfg.BatchSize, cfg.PrecomputeFactor, cfg.C, cfg.Bitsize)

	// 4) 准备结果 HostSlice，长度 = batchSize
	out := make(icicle_core.HostSlice[icicle_bls12_381.Projective], batchSize)

	// 5) 调用 MSM：一次性算出 batchSize 个结果
	st := icicle_msm.Msm(scalarsDev, G1Lagrange, &cfg, out)
	if st != icicle_runtime.Success {
		return nil, st
	}

	// 6) Projective → gnark Affine（= kzg.Digest）
	res := make([]kzg.Digest, batchSize)
	for i := 0; i < batchSize; i++ {
		aff := blsProjectiveToGnarkAffine(out[i])
		res[i] = kzg.Digest(aff)
	}
	return res, icicle_runtime.Success
}

func OnDeviceOpen(p []fr.Element, point fr.Element, base icicle_core.DeviceSlice) (kzg.OpeningProof, icicle_runtime.EIcicleError) {
	var proof kzg.OpeningProof

	// 1) 声明值（CPU 做即可，代价可忽略）
	proof.ClaimedValue = eval(p, point)

	// 2) 构造 H(X) = (p(X)-p(point)) / (X-point)
	_p := make([]fr.Element, len(p))
	copy(_p, p)
	h := dividePolyByXminusA(_p, proof.ClaimedValue, point)

	// 3) 对 H 做一次设备端承诺：commit(H)
	//    注意 bases 需要与标量长度一致，这里对子片到 len(h)
	subBase := base.RangeTo(len(h), false)
	dig, st := OnDeviceCommit(h, subBase)
	if st != icicle_runtime.Success {
		return kzg.OpeningProof{}, st
	}

	// 4) 组装返回值
	proof.H = kzg.Digest(dig) // Digest 是 G1Affine 的别名
	return proof, icicle_runtime.Success
}

func eval(p []fr.Element, point fr.Element) fr.Element {
	var res fr.Element
	n := len(p)
	if n == 0 {
		return res // 0
	}
	res.Set(&p[n-1])
	for i := n - 2; i >= 0; i-- {
		res.Mul(&res, &point).Add(&res, &p[i])
	}
	return res
}

func dividePolyByXminusA(f []fr.Element, fa, a fr.Element) []fr.Element {
	// f <- f - f(a)
	f[0].Sub(&f[0], &fa)

	var t fr.Element
	for i := len(f) - 2; i >= 0; i-- {
		t.Mul(&f[i+1], &a)
		f[i].Add(&f[i], &t)
	}
	return f[1:]
}

// 把 fr.Element 变成 icicle NTT 需要的 CosetGen 表示（uint32 limbs*2）
func CosetGenToIcicle(g fr.Element) (out [fr.Limbs * 2]uint32) {
	bits := g.Bits() // [fr.Limbs]uint64
	limbs := icicle_core.ConvertUint64ArrToUint32Arr(bits[:])
	copy(out[:], limbs[:fr.Limbs*2])
	return
}

func INttOnDevice(aDev icicle_core.DeviceSlice) icicle_runtime.EIcicleError {
	cfg := icicle_ntt.GetDefaultNttConfig()
	cfg.Ordering = icicle_core.KNN
	return icicle_ntt.Ntt(aDev, icicle_core.KInverse, &cfg, aDev)
}

func INttOnDeviceStream(
	dev icicle_core.DeviceSlice,
	stream icicle_runtime.Stream,
) icicle_runtime.EIcicleError {
	cfg := icicle_ntt.GetDefaultNttConfig()
	cfg.StreamHandle = stream
	cfg.IsAsync = true

	cfg.Ordering = icicle_core.KNN

	return icicle_ntt.Ntt(dev, icicle_core.KInverse, &cfg, dev)
}

// NttOnDevice: 正向NTT（就地 in-place）。如果 isCoset=true 则做 coset-NTT。
// 约定：输入/输出都在 Montgomery 表示。
func NttOnDevice(aDev icicle_core.DeviceSlice) icicle_runtime.EIcicleError {

	cfg := icicle_ntt.GetDefaultNttConfig()
	// KMN = 常用的正向排列（匹配 gnark/icicle 的用法）
	cfg.Ordering = icicle_core.KNN
	return icicle_ntt.Ntt(aDev, icicle_core.KForward, &cfg, aDev)
}
func NttOnDeviceStream(
	dev icicle_core.DeviceSlice,
	stream icicle_runtime.Stream,
) icicle_runtime.EIcicleError {
	cfg := icicle_ntt.GetDefaultNttConfig()
	cfg.StreamHandle = stream
	cfg.IsAsync = true

	cfg.Ordering = icicle_core.KNN

	return icicle_ntt.Ntt(dev, icicle_core.KForward, &cfg, dev)
}

// VecMulOnDevice: 逐元素乘法 acc = acc * other（模 p），就地写回 acc。
// 注意：icicle 的 vecOps 期望“非 Montgomery”表示；如果你的数据现在是 Montgomery，
// 请先调用 MontConvOnDevice(s, false) 转出，再做乘法，必要时乘完再转回。
func VecMulOnDevice(acc, other icicle_core.DeviceSlice) icicle_runtime.EIcicleError {

	vecCfg := icicle_core.DefaultVecOpsConfig()
	return icicle_vecops.VecOp(acc, other, acc, vecCfg, icicle_core.Mul)
}

func VecMulOnDeviceStream(
	acc, other icicle_core.DeviceSlice,
	stream icicle_runtime.Stream,
) icicle_runtime.EIcicleError {
	cfg := icicle_core.DefaultVecOpsConfig()
	cfg.StreamHandle = stream
	cfg.IsAsync = true

	return icicle_vecops.VecOp(acc, other, acc, cfg, icicle_core.Mul)
}

// MontConvOnDevice: 标量数组的 Montgomery <-> 非Montgomery 转换（就地）
// into=true  => ToMontgomery
// into=false => FromMontgomery
func MontConvOnDevice(s icicle_core.DeviceSlice, into bool) icicle_runtime.EIcicleError {
	if into {
		return icicle_bls12_381.ToMontgomery(s)
	}
	return icicle_bls12_381.FromMontgomery(s)
}

func OnDeviceCommitStream(p []fr.Element, G1Device icicle_core.DeviceSlice, stream icicle_runtime.Stream) (kzg.Digest, icicle_runtime.EIcicleError) {
	// 1) 把标量拷到设备
	host := icicle_core.HostSliceFromElements(p)

	var scalarsDev icicle_core.DeviceSlice
	host.CopyToDevice(&scalarsDev, true)

	// 2) 配置 MSM
	cfg := icicle_msm.GetDefaultMSMConfig()
	// gnark-crypto 的标量/基点默认在 Montgomery 形式
	cfg.StreamHandle = stream
	cfg.AreScalarsMontgomeryForm = true
	cfg.AreBasesMontgomeryForm = false

	// 3) 运行 MSM（输出 1 个 projective 点）
	out := make(icicle_core.HostSlice[icicle_bls12_381.Projective], 1)
	st := icicle_msm.Msm(scalarsDev, G1Device, &cfg, out)

	_ = scalarsDev.Free()

	// 4) 转成 gnark 的 Affine（= kzg.Digest）
	res := blsProjectiveToGnarkAffine(out[0])

	// 5) 清理设备内存
	if st != icicle_runtime.Success {
		return kzg.Digest{}, st
	}

	return kzg.Digest(res), icicle_runtime.Success
}

// VecMulBatchOnDevice:
//
//	accBatch, otherBatch: 长度均为 batchSize * vecLen 的 DeviceSlice，按
//	    [batch][vecLen] row-major 扁平化。
//	语义：对每个 batch i，做 acc[i] = acc[i] * other[i]（逐元素相乘）。
//	注意：要求输入是 non-Montgomery（canonical）表示；如果现在是 Montgomery，
//	请先在外层调用 MontConvOnDevice(s, false)。
func VecMulBatchOnDevice(
	accBatch icicle_core.DeviceSlice,
	otherBatch icicle_core.DeviceSlice,
	batchSize int,
) icicle_runtime.EIcicleError {

	cfg := icicle_core.DefaultVecOpsConfig()

	// 打开 batch 支持：解释为 batchSize 条向量，每条长度 = len(accBatch)/batchSize
	cfg.BatchSize = int32(batchSize)
	// 我们采用 row-major 扁平化布局：每条向量是连续的一段，因此 ColumnsBatch = false
	cfg.ColumnsBatch = false

	return icicle_vecops.VecOp(
		accBatch,
		otherBatch,
		accBatch, // 就地写回 acc
		cfg,
		icicle_core.Mul, // 逐元素乘法
	)
}

// VecMulBatchOnDeviceStream:
// 和 VecMulBatchOnDevice 相同，但运行在给定的 CUDA stream 上，并可异步执行。
// - accBatch / otherBatch: [batchSize][vecLen] 扁平化后存放在 DeviceSlice 中。
// - stream: 外层 pipeline 已经创建好的 runtime.Stream。
func VecMulBatchOnDeviceStream(
	accBatch icicle_core.DeviceSlice,
	otherBatch icicle_core.DeviceSlice,
	batchSize int,
	stream icicle_runtime.Stream,
) icicle_runtime.EIcicleError {

	cfg := icicle_core.DefaultVecOpsConfig()

	cfg.StreamHandle = stream
	cfg.IsAsync = true

	cfg.BatchSize = int32(batchSize)
	cfg.ColumnsBatch = false

	return icicle_vecops.VecOp(
		accBatch,
		otherBatch,
		accBatch, // in-place
		cfg,
		icicle_core.Mul,
	)
}

// NttBatchOnDevice:
// 对 batchSize 条向量同时做正向 NTT。
// dataBatch: [batchSize][vecLen] 扁平化后的 DeviceSlice。
// 要求：NTT 域已经通过 InitDomain 初始化好，vecLen 是当前域的大小。
func NttBatchOnDevice(
	dataBatch icicle_core.DeviceSlice,
	batchSize int,
) icicle_runtime.EIcicleError {

	cfg := icicle_ntt.GetDefaultNttConfig()
	cfg.BatchSize = int32(batchSize)
	cfg.ColumnsBatch = false // row-major: 每条向量是连续的一段
	cfg.Ordering = icicle_core.KNN

	return icicle_ntt.Ntt(
		dataBatch,
		icicle_core.KForward,
		&cfg,
		dataBatch, // in-place
	)
}

// INttBatchOnDevice:
// 对 batchSize 条向量同时做逆 NTT（回到 time domain）。
func INttBatchOnDevice(
	dataBatch icicle_core.DeviceSlice,
	batchSize int,
) icicle_runtime.EIcicleError {

	cfg := icicle_ntt.GetDefaultNttConfig()
	cfg.BatchSize = int32(batchSize)
	cfg.ColumnsBatch = false
	cfg.Ordering = icicle_core.KNN

	return icicle_ntt.Ntt(
		dataBatch,
		icicle_core.KInverse,
		&cfg,
		dataBatch, // in-place
	)
}

// NttBatchOnDeviceStream:
// 在给定 stream 上，对 batchSize 条向量做正向 NTT。
// dataBatch: [batchSize][vecLen] 扁平化存放在 DeviceSlice 中。
func NttBatchOnDeviceStream(
	dataBatch icicle_core.DeviceSlice,
	batchSize int,
	stream icicle_runtime.Stream,
) icicle_runtime.EIcicleError {

	cfg := icicle_ntt.GetDefaultNttConfig()

	cfg.StreamHandle = stream
	cfg.IsAsync = true

	cfg.BatchSize = int32(batchSize)
	cfg.ColumnsBatch = false
	cfg.Ordering = icicle_core.KNN

	return icicle_ntt.Ntt(
		dataBatch,
		icicle_core.KForward,
		&cfg,
		dataBatch,
	)
}

// INttBatchOnDeviceStream:
// 在给定 stream 上，对 batchSize 条向量做逆 NTT。
func INttBatchOnDeviceStream(
	dataBatch icicle_core.DeviceSlice,
	batchSize int,
	stream icicle_runtime.Stream,
) icicle_runtime.EIcicleError {

	cfg := icicle_ntt.GetDefaultNttConfig()

	cfg.StreamHandle = stream
	cfg.IsAsync = true

	cfg.BatchSize = int32(batchSize)
	cfg.ColumnsBatch = false
	cfg.Ordering = icicle_core.KNN

	return icicle_ntt.Ntt(
		dataBatch,
		icicle_core.KInverse,
		&cfg,
		dataBatch,
	)
}

// ============= precompute optimization ===================
// OnDeviceCommitWithPrecompute 使用预计算的 bases 做 MSM
// p: 多项式系数
// precomputedBases: 预计算的 bases（DeviceSlice），长度应该匹配 N * PrecomputeFactor
// cfg: MSM 配置（必须与预计算时使用的配置一致）
// 返回：kzg.Digest
func OnDeviceCommitWithPrecompute(p []fr.Element, precomputedBases icicle_core.DeviceSlice, cfg *icicle_core.MSMConfig) (kzg.Digest, icicle_runtime.EIcicleError) {

	// 1) 把标量拷到设备
	host := icicle_core.HostSliceFromElements(p)
	var scalarsDev icicle_core.DeviceSlice
	host.CopyToDevice(&scalarsDev, true)
	defer scalarsDev.Free()

	// 2) 运行 MSM（输出 1 个 projective 点）
	out := make(icicle_core.HostSlice[icicle_bls12_381.Projective], 1)
	st := icicle_msm.Msm(scalarsDev, precomputedBases, cfg, out)
	if st != icicle_runtime.Success {
		return kzg.Digest{}, st
	}

	// 3) 转成 gnark 的 Affine（= kzg.Digest）
	res := blsProjectiveToGnarkAffine(out[0])

	return kzg.Digest(res), icicle_runtime.Success
}

func OnDeviceOpenWithPrecompute(
	p []fr.Element,
	point fr.Element,
	base icicle_core.DeviceSlice,
	precomputedBases icicle_core.DeviceSlice,
	cfg *icicle_core.MSMConfig,
) (kzg.OpeningProof, icicle_runtime.EIcicleError) {
	var proof kzg.OpeningProof

	// 1) 声明值（CPU 做即可，代价可忽略）
	proof.ClaimedValue = eval(p, point)

	// 2) 构造 H(X) = (p(X)-p(point)) / (X-point)
	_p := make([]fr.Element, len(p))
	copy(_p, p)
	h := dividePolyByXminusA(_p, proof.ClaimedValue, point)

	// 3) 对 H 做一次设备端承诺：commit(H)，使用预计算的 bases
	hLen := len(h)
	precomputeFactor := int(cfg.PrecomputeFactor)
	neededLen := hLen * precomputeFactor
	precompSubBase := precomputedBases.RangeTo(neededLen, false)
	dig, st := OnDeviceCommitWithPrecompute(h, precompSubBase, cfg)

	if st != icicle_runtime.Success {
		return kzg.OpeningProof{}, st
	}

	// 4) 组装返回值
	proof.H = kzg.Digest(dig) // Digest 是 G1Affine 的别名
	return proof, icicle_runtime.Success
}

func OnDeviceCommitBatchLROWithPrecompute(
	polys [][]fr.Element,
	precomputedBases icicle_core.DeviceSlice,
	cfg *icicle_core.MSMConfig,
) ([]kzg.Digest, icicle_runtime.EIcicleError) {
	batchSize := len(polys)
	if batchSize == 0 {
		return nil, icicle_runtime.Success
	}

	// 确认所有多项式长度一致
	N := len(polys[0])
	for i := 1; i < batchSize; i++ {
		if len(polys[i]) != N {
			log.Printf("[OnDeviceCommitBatchLROWithPrecompute] polys have different lengths: N=%d, len(polys[%d])=%d",
				N, i, len(polys[i]))
			return nil, icicle_runtime.InvalidArgument
		}
	}

	// 1) 把 [L, R, O] flatten 成一个大标量数组：L || R || O
	flatten := make([]fr.Element, 0, batchSize*N)
	for i := 0; i < batchSize; i++ {
		flatten = append(flatten, polys[i]...)
	}

	// 2) HostSlice → DeviceSlice
	host := icicle_core.HostSliceFromElements(flatten)
	var scalarsDev icicle_core.DeviceSlice
	host.CopyToDevice(&scalarsDev, true)
	defer scalarsDev.Free()

	// 3) 准备结果 HostSlice，长度 = batchSize
	out := make(icicle_core.HostSlice[icicle_bls12_381.Projective], batchSize)

	// 4) 调用 MSM：使用预计算的基点
	st := icicle_msm.Msm(scalarsDev, precomputedBases, cfg, out)
	if st != icicle_runtime.Success {
		return nil, st
	}

	// 5) Projective → gnark Affine（= kzg.Digest）
	res := make([]kzg.Digest, batchSize)
	for i := 0; i < batchSize; i++ {
		aff := blsProjectiveToGnarkAffine(out[i])
		res[i] = kzg.Digest(aff)
	}

	return res, icicle_runtime.Success
}

func OnDeviceCommitStreamWithPrecompute(
	p []fr.Element,
	precomputedBases icicle_core.DeviceSlice,
	cfg *icicle_core.MSMConfig,
	stream icicle_runtime.Stream,
) (kzg.Digest, icicle_runtime.EIcicleError) {
	// 1) 把标量拷到设备
	host := icicle_core.HostSliceFromElements(p)
	var scalarsDev icicle_core.DeviceSlice
	host.CopyToDevice(&scalarsDev, true)

	// 2) 配置 MSM：使用传入的配置，但设置 stream 和异步标志
	cfgCopy := *cfg // 复制配置，避免修改原始配置
	cfgCopy.StreamHandle = stream
	cfgCopy.IsAsync = true

	// 3) 运行 MSM（输出 1 个 projective 点）
	out := make(icicle_core.HostSlice[icicle_bls12_381.Projective], 1)
	st := icicle_msm.Msm(scalarsDev, precomputedBases, &cfgCopy, out)

	_ = scalarsDev.Free()

	// 4) 转成 gnark 的 Affine（= kzg.Digest）
	if st != icicle_runtime.Success {
		return kzg.Digest{}, st
	}

	res := blsProjectiveToGnarkAffine(out[0])
	return kzg.Digest(res), icicle_runtime.Success
}
