//go:build icicle

package bls12_381_gpu

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	"github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381"
	icicle_ntt "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381/ntt"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

// 把 bls12381 的 ROU（Montgomery form）转成 icicle scalar field（按文档示例）:contentReference[oaicite:3]{index=3}
func initDomain(t *testing.T, logN int) {
	t.Helper()

	icicle_runtime.LoadBackendFromEnvOrDefault()
	device := icicle_runtime.CreateDevice("CUDA", 0)
	icicle_runtime.SetDevice(&device)

	cfg := icicle_core.GetDefaultNTTInitDomainConfig()

	rouMont, err := fft.Generator(uint64(1 << logN))
	if err != nil {
		t.Fatalf("fft.Generator failed: %v", err)
	}
	rou := rouMont.Bits()

	var rouIcicle bls12381.ScalarField
	rouIcicle.FromLimbs(icicle_core.ConvertUint64ArrToUint32Arr(rou[:]))

	if st := icicle_ntt.InitDomain(rouIcicle, cfg); st != icicle_runtime.Success {
		t.Fatalf("ntt.InitDomain failed: %s", st.AsString())
	}
	t.Cleanup(func() { _ = icicle_ntt.ReleaseDomain() })
}

// 生成一个随机 icicle scalar（这里用 bls12381.GenerateScalars 简化）
func randScalars(n int) icicle_core.HostSlice[bls12381.ScalarField] {
	return bls12381.GenerateScalars(n)
}

func scalarOne() bls12381.ScalarField {
	var one bls12381.ScalarField
	one.FromLimbs([]uint32{1}) // 若你这版不接受这种写法，就用“把 gnark 的 1 转 limbs”那套
	return one
}

// 用反射做等价比较，避免 ScalarField 不可比较时编译失败
func eqScalar(a, b bls12381.ScalarField) bool { return reflect.DeepEqual(a, b) }

func TestBatchNTT_RowMajor_EqualsPerRowNTT(t *testing.T) {
	logN := 12
	N := 1 << logN
	B := 4

	initDomain(t, logN)

	// row-major flatten: [B][N] => length B*N
	in := randScalars(B * N)

	// 1) batched NTT
	cfgB := icicle_ntt.GetDefaultNttConfig()
	cfgB.BatchSize = int32(B)
	cfgB.ColumnsBatch = false // row-major：每一行是一条独立向量 :contentReference[oaicite:4]{index=4}

	outBatch := make(icicle_core.HostSlice[bls12381.ScalarField], B*N)
	if st := icicle_ntt.Ntt(in, icicle_core.KForward, &cfgB, outBatch); st != icicle_runtime.Success {
		t.Fatalf("batched ntt failed: %s", st.AsString())
	}

	// 2) per-row NTT（BatchSize=1，逐行做），结果应与 batched 一致
	cfg1 := icicle_ntt.GetDefaultNttConfig()
	cfg1.BatchSize = 1
	cfg1.ColumnsBatch = false

	for i := 0; i < B; i++ {
		rowIn := in[i*N : (i+1)*N]
		rowOut := make(icicle_core.HostSlice[bls12381.ScalarField], N)
		if st := icicle_ntt.Ntt(rowIn, icicle_core.KForward, &cfg1, rowOut); st != icicle_runtime.Success {
			t.Fatalf("row ntt failed (row=%d): %s", i, st.AsString())
		}
		for j := 0; j < N; j++ {
			if !eqScalar(outBatch[i*N+j], rowOut[j]) {
				t.Fatalf("mismatch at row=%d col=%d", i, j)
			}
		}
	}
}
func TestCosetGen_EqualsCoeffScaledThenStdNTT(t *testing.T) {
	logN := 10
	N := 1 << logN

	initDomain(t, logN)

	// ===== 1) 随机系数 a (用 gnark-crypto fr.Element，方便做乘法与幂) =====
	// 注意：gnark-crypto 的 fr.Element 默认是 Montgomery 表示；icicle-gnark 的 NTT 对 fr.Element 的路径就是这么用的
	a := make([]fr.Element, N)
	for i := 0; i < N; i++ {
		_, _ = a[i].SetRandom()
	}

	// 随机 coset 生成元 c（gnark-crypto fr.Element）
	var cFr fr.Element
	for {
		_, _ = cFr.SetRandom()
		if !cFr.IsZero() {
			break
		}
	}

	// fr.Element -> [8]uint32 limbs（BLS12-381 Fr: 4*64bit => 8*32bit）
	cBits := cFr.Bits() // [fr.Limbs]uint64
	c32 := icicle_core.ConvertUint64ArrToUint32Arr(cBits[:])

	var cLimbs8 [fr.Limbs * 2]uint32 // fr.Limbs=4 => [8]uint32
	copy(cLimbs8[:], c32[:fr.Limbs*2])

	cfgCoset := icicle_ntt.GetDefaultNttConfig()
	cfgCoset.BatchSize = 1
	cfgCoset.ColumnsBatch = false
	cfgCoset.CosetGen = cLimbs8 // ✅ 注意这里是 [8]uint32

	// ===== 2) outCoset = NTT(a, CosetGen=c) =====

	outCoset := make(icicle_core.HostSlice[fr.Element], N)
	inA := icicle_core.HostSliceFromElements(a)
	if st := icicle_ntt.Ntt(inA, icicle_core.KForward, &cfgCoset, outCoset); st != icicle_runtime.Success {
		t.Fatalf("coset ntt failed: %s", st.AsString())
	}

	// ===== 3) 构造 aScaled[j] = a[j] * c^j =====
	aScaled := make([]fr.Element, N)
	var pow fr.Element
	pow.SetOne()
	for j := 0; j < N; j++ {
		aScaled[j].Mul(&a[j], &pow) // a[j] * c^j
		pow.Mul(&pow, &cFr)         // pow *= c
	}

	// ===== 4) outStd = NTT(aScaled, CosetGen=1/默认) =====
	cfgStd := icicle_ntt.GetDefaultNttConfig()
	cfgStd.BatchSize = 1
	cfgStd.ColumnsBatch = false
	// 关键：这里不要设置 CosetGen（保持“标准 NTT”）
	outStd := make(icicle_core.HostSlice[fr.Element], N)
	inScaled := icicle_core.HostSliceFromElements(aScaled)
	if st := icicle_ntt.Ntt(inScaled, icicle_core.KForward, &cfgStd, outStd); st != icicle_runtime.Success {
		t.Fatalf("std ntt failed: %s", st.AsString())
	}

	// ===== 5) 比较 outCoset == outStd =====
	for i := 0; i < N; i++ {
		if outCoset[i] != outStd[i] {
			t.Fatalf("coset mismatch at %d", i)
		}
	}
}

func TestBatchCosetNTT_RowMajor_EqualsPerRowCosetNTT(t *testing.T) {
	logN := 12
	N := 1 << logN
	B := 4

	initDomain(t, logN)

	// ===== 1) 随机输入（用 fr.Element，方便后面也能做 CPU scaling）=====
	in := make([]fr.Element, B*N)
	for i := 0; i < len(in); i++ {
		_, _ = in[i].SetRandom()
	}

	// 随机 coset gen c（非 0）
	var c fr.Element
	for {
		_, _ = c.SetRandom()
		if !c.IsZero() {
			break
		}
	}
	// fr.Element -> [8]uint32
	cBits := c.Bits()
	c32 := icicle_core.ConvertUint64ArrToUint32Arr(cBits[:])
	var cLimbs [fr.Limbs * 2]uint32
	copy(cLimbs[:], c32[:fr.Limbs*2])

	// ===== 2) Batched coset NTT (row-major) =====
	cfgB := icicle_ntt.GetDefaultNttConfig()
	cfgB.BatchSize = int32(B)
	cfgB.ColumnsBatch = false
	cfgB.CosetGen = cLimbs

	outBatch := make(icicle_core.HostSlice[fr.Element], B*N)
	if st := icicle_ntt.Ntt(icicle_core.HostSliceFromElements(in), icicle_core.KForward, &cfgB, outBatch); st != icicle_runtime.Success {
		t.Fatalf("batched coset ntt failed: %s", st.AsString())
	}

	// ===== 3) Per-row coset NTT (BatchSize=1) =====
	cfg1 := icicle_ntt.GetDefaultNttConfig()
	cfg1.BatchSize = 1
	cfg1.ColumnsBatch = false
	cfg1.CosetGen = cLimbs

	for r := 0; r < B; r++ {
		rowIn := in[r*N : (r+1)*N]
		rowOut := make(icicle_core.HostSlice[fr.Element], N)

		if st := icicle_ntt.Ntt(icicle_core.HostSliceFromElements(rowIn), icicle_core.KForward, &cfg1, rowOut); st != icicle_runtime.Success {
			t.Fatalf("row coset ntt failed (row=%d): %s", r, st.AsString())
		}

		for j := 0; j < N; j++ {
			if outBatch[r*N+j] != rowOut[j] {
				t.Fatalf("mismatch row=%d idx=%d", r, j)
			}
		}
	}
}

func TestBatchCosetNTT_RowMajor_EqualsCoeffScaledThenStdNTT_PerRow(t *testing.T) {
	logN := 12
	N := 1 << logN
	B := 4

	initDomain(t, logN)

	// 输入 in: [B][N] row-major flatten
	in := make([]fr.Element, B*N)
	for i := 0; i < len(in); i++ {
		_, _ = in[i].SetRandom()
	}

	// coset gen c
	var c fr.Element
	for {
		_, _ = c.SetRandom()
		if !c.IsZero() {
			break
		}
	}
	cBits := c.Bits()
	c32 := icicle_core.ConvertUint64ArrToUint32Arr(cBits[:])
	var cLimbs [fr.Limbs * 2]uint32
	copy(cLimbs[:], c32[:fr.Limbs*2])

	// 1) GPU: batched coset NTT
	cfgCosetB := icicle_ntt.GetDefaultNttConfig()
	cfgCosetB.BatchSize = int32(B)
	cfgCosetB.ColumnsBatch = false
	cfgCosetB.CosetGen = cLimbs

	outCosetBatch := make(icicle_core.HostSlice[fr.Element], B*N)
	if st := icicle_ntt.Ntt(icicle_core.HostSliceFromElements(in), icicle_core.KForward, &cfgCosetB, outCosetBatch); st != icicle_runtime.Success {
		t.Fatalf("batched coset ntt failed: %s", st.AsString())
	}

	// 2) baseline: per-row scale by c^j, then std NTT (icicle)
	cfgStd1 := icicle_ntt.GetDefaultNttConfig()
	cfgStd1.BatchSize = 1
	cfgStd1.ColumnsBatch = false
	// 不设置 CosetGen => 标准 NTT

	for r := 0; r < B; r++ {
		// aScaled[j] = a[j] * c^j
		row := in[r*N : (r+1)*N]
		scaled := make([]fr.Element, N)
		copy(scaled, row)

		var pow fr.Element
		pow.SetOne()
		for j := 0; j < N; j++ {
			scaled[j].Mul(&scaled[j], &pow)
			pow.Mul(&pow, &c)
		}

		outStd := make(icicle_core.HostSlice[fr.Element], N)
		if st := icicle_ntt.Ntt(icicle_core.HostSliceFromElements(scaled), icicle_core.KForward, &cfgStd1, outStd); st != icicle_runtime.Success {
			t.Fatalf("std ntt failed (row=%d): %s", r, st.AsString())
		}

		for j := 0; j < N; j++ {
			if outCosetBatch[r*N+j] != outStd[j] {
				t.Fatalf("mismatch row=%d idx=%d", r, j)
			}
		}
	}
}
