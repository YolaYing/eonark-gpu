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

	// 2) 配置 MSM
	cfg := icicle_msm.GetDefaultMSMConfig()
	// gnark-crypto 的标量/基点默认在 Montgomery 形式
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

// NttOnDevice: 正向NTT（就地 in-place）。如果 isCoset=true 则做 coset-NTT。
// 约定：输入/输出都在 Montgomery 表示。
func NttOnDevice(aDev icicle_core.DeviceSlice) icicle_runtime.EIcicleError {

	cfg := icicle_ntt.GetDefaultNttConfig()
	// KMN = 常用的正向排列（匹配 gnark/icicle 的用法）
	cfg.Ordering = icicle_core.KNN
	return icicle_ntt.Ntt(aDev, icicle_core.KForward, &cfg, aDev)
}

// VecMulOnDevice: 逐元素乘法 acc = acc * other（模 p），就地写回 acc。
// 注意：icicle 的 vecOps 期望“非 Montgomery”表示；如果你的数据现在是 Montgomery，
// 请先调用 MontConvOnDevice(s, false) 转出，再做乘法，必要时乘完再转回。
func VecMulOnDevice(acc, other icicle_core.DeviceSlice) icicle_runtime.EIcicleError {

	vecCfg := icicle_core.DefaultVecOpsConfig()
	return icicle_vecops.VecOp(acc, other, acc, vecCfg, icicle_core.Mul)
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
