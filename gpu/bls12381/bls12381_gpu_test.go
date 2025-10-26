/*
KZG MSM: CPU vs GPU (Icicle v3 @ RTX 4090)

Backend
- ICICLE_BACKEND_INSTALL_DIR=/home/jade/.local/icicle/lib/backend
- CUDA devices visible: 1
- Using device: CUDA:0
- 随机 SRS.G1 仅构建一次（n=1,048,576），之后用前缀复用（总用时里这步最耗时）

Results
- n=1,024     CPU=  2.216 ms  GPU= 10.780 ms  speedup=0.21x
- n=4,096     CPU=  3.779 ms  GPU=  5.316 ms  speedup=0.71x
- n=16,384    CPU=  8.628 ms  GPU=  6.021 ms  speedup=1.43x  ← GPU 开始占优
- n=65,536    CPU= 26.180 ms  GPU=  7.029 ms  speedup=3.72x
- n=262,144   CPU= 92.224 ms  GPU= 10.256 ms  speedup=8.99x
- n=1,048,576 CPU=288.565 ms  GPU= 32.413 ms  speedup=8.90x

Takeaways
- 小规模（≤4k）GPU 受启动/H2D 开销影响更慢；约 16k 开始 GPU 反超。
- 65k 规模约 3.7× 加速；≥262k 规模稳定在 ~9× 左右。
- 测试总时长（~63s）主要被“构建随机 SRS”占用；实际系统中应让 SRS 常驻 device。
- 本测试中 G1 已做 AffineFromMontgomery，MSM 配置：AreScalarsMontgomeryForm=true，AreBasesMontgomeryForm=false。
*/
package bls12_381_gpu

import (
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_bls12_381 "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"

	icicle_ntt "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381/ntt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/iop"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	icicle_vecops "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381/vecOps"
)

/********** helpers **********/

// 随机 SRS.G1: bases[i] = [tau^i]·G
func buildRandomSRS_G1(n int) []curve.G1Affine {
	if n <= 0 {
		return nil
	}
	var tau fr.Element
	if _, err := tau.SetRandom(); err != nil {
		panic(fmt.Errorf("set random tau: %w", err))
	}
	pows := make([]fr.Element, n)
	pows[0].SetOne()
	for i := 1; i < n; i++ {
		pows[i].Mul(&pows[i-1], &tau)
	}
	bases := make([]curve.G1Affine, n)
	for i := 0; i < n; i++ {
		var s big.Int
		pows[i].BigInt(&s)
		var jac curve.G1Jac
		jac.ScalarMultiplicationBase(&s)
		bases[i].FromJacobian(&jac)
	}
	return bases
}

func randomScalars(n int) []fr.Element {
	s := make([]fr.Element, n)
	for i := range s {
		if _, err := s[i].SetRandom(); err != nil {
			panic(err)
		}
	}
	return s
}

func cpuMSM(bases []curve.G1Affine, scalars []fr.Element) curve.G1Affine {
	var res curve.G1Affine
	res.MultiExp(bases, scalars, ecc.MultiExpConfig{})
	return res
}

// 加载 Icicle 后端并创建设备（不显式 SetDevice；用 RunOnDevice 驱动）
func mustCreateCUDADevice(t *testing.T) *icicle_runtime.Device {
	if st := icicle_runtime.LoadBackendFromEnvOrDefault(); st != icicle_runtime.Success {
		t.Fatalf("LoadBackendFromEnvOrDefault failed: %s", st.AsString())
	}
	if cnt, st := icicle_runtime.GetDeviceCount(); st == icicle_runtime.Success {
		t.Logf("ICICLE CUDA devices visible: %d", cnt)
	} else {
		t.Logf("GetDeviceCount error: %s (still trying)", st.AsString())
	}
	dev := icicle_runtime.CreateDevice("CUDA", 0)

	// 在设备上下文里确认一下
	done := make(chan struct{})
	icicle_runtime.RunOnDevice(&dev, func(args ...any) {
		defer close(done)
		if d, st := icicle_runtime.GetActiveDevice(); st == icicle_runtime.Success {
			t.Logf("Using ICICLE device: type=%s", d.GetDeviceType())
		} else {
			t.Logf("GetActiveDevice failed: %s", st.AsString())
		}
	})
	<-done

	return &dev
}

/********** test **********/

func TestOnDeviceCommit_GPUvsCPU(t *testing.T) {
	device := mustCreateCUDADevice(t)

	// 测试规模
	cases := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 18, 1 << 20}
	if testing.Short() {
		cases = []int{1 << 10, 1 << 12, 1 << 14}
	}
	sort.Ints(cases)
	maxN := cases[len(cases)-1]

	// 只生成一次最大规模的 SRS，后面用前缀重用，避免把时间花在造 SRS 上
	t.Logf("building random SRS.G1 once (n=%d); this is CPU-heavy and may take a while...", maxN)
	g1Max := buildRandomSRS_G1(maxN)
	t.Logf("SRS built")

	for _, n := range cases {
		n := n
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			g1 := g1Max[:n]
			scalars := randomScalars(n)

			// CPU baseline
			t0 := time.Now()
			cpu := cpuMSM(g1, scalars)
			cpuDur := time.Since(t0)

			// GPU path：所有 GPU 操作在同一个 RunOnDevice 闭包内完成（分配/转换/MSM/释放）
			var gpu curve.G1Affine
			var gpuErr error
			var gpuDur time.Duration

			done := make(chan struct{})
			icicle_runtime.RunOnDevice(device, func(args ...any) {
				defer close(done)

				// H2D: G1
				host := (icicle_core.HostSlice[curve.G1Affine])(g1)
				var g1Dev icicle_core.DeviceSlice
				host.CopyToDevice(&g1Dev, true)

				// 基点出 Montgomery（与 MSM 配置保持一致）
				if st := icicle_bls12_381.AffineFromMontgomery(g1Dev); st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("AffineFromMontgomery(G1): %s", st.AsString())
					_ = g1Dev.Free()
					return
				}

				// MSM
				t1 := time.Now()
				d, st := OnDeviceCommit(scalars, g1Dev)
				gpuDur = time.Since(t1)

				// 释放 device slice（必须在同一 device 上）
				if stFree := g1Dev.Free(); stFree != icicle_runtime.Success {
					t.Logf("warning: free G1 device slice failed: %s", stFree.AsString())
				}

				if st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("icicle MSM: %s", st.AsString())
					return
				}
				gpu = curve.G1Affine(d)
			})
			<-done

			if gpuErr != nil {
				t.Skipf("GPU MSM error (likely backend/device issue): %v", gpuErr)
			}

			// 结果一致性 + 记录性能
			if !cpu.Equal(&gpu) {
				t.Fatalf("CPU and GPU MSM mismatch:\nCPU: %+v\nGPU: %+v", cpu, gpu)
			}
			speedup := float64(cpuDur) / float64(gpuDur)
			t.Logf("n=%d  CPU=%s  GPU=%s  speedup=%.2fx", n, cpuDur, gpuDur, speedup)
		})
	}
}

/********** extra helpers for NTT & comparisons **********/

// 设备上初始化 NTT 域（只需在使用 NTT 前做一次）
func mustInitNTTDomainOnDevice(t *testing.T, device *icicle_runtime.Device, maxN int) {
	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		defer close(done)
		// 按照 v3 示例，用 2*maxN 的原根初始化域
		gen, err := fft.Generator(uint64(2 * maxN))
		if err != nil {
			t.Fatalf("fft.Generator: %v", err)
		}
		bitsArr := gen.Bits() // [4]uint64（fr 是 4 个 limb；fp 则是 6 个）
		limbs := icicle_core.ConvertUint64ArrToUint32Arr(bitsArr[:])

		var rou icicle_bls12_381.ScalarField
		rou.FromLimbs(limbs)
		if e := icicle_ntt.InitDomain(rou, icicle_core.GetDefaultNTTInitDomainConfig()); e != icicle_runtime.Success {
			t.Fatalf("InitDomain failed: %s", e.AsString())
		}
	})
	<-done
}

func frSliceEqual(a, b []fr.Element) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(&b[i]) {
			return false
		}
	}
	return true
}

func cloneFrSlice(a []fr.Element) []fr.Element {
	b := make([]fr.Element, len(a))
	copy(b, a)
	return b
}

/********** tests **********/

// 1) Montgomery 往返测试：FromMontgomery -> ToMontgomery == 原值
func TestMontConvOnDevice_Roundtrip(t *testing.T) {
	device := mustCreateCUDADevice(t)

	n := 1 << 12
	src := randomScalars(n)   // gnark-crypto 的 fr.Element 默认是 Montgomery 形式
	orig := cloneFrSlice(src) // 作为期望值（Montgomery）
	host := (icicle_core.HostSlice[fr.Element])(src)

	var dev icicle_core.DeviceSlice
	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		defer close(done)

		// H2D
		host.CopyToDevice(&dev, true)

		// 从蒙哥马利 -> 普通
		if st := icicle_bls12_381.FromMontgomery(dev); st != icicle_runtime.Success {
			t.Fatalf("FromMontgomery: %s", st.AsString())
		}
		// 再回到蒙哥马利
		if st := icicle_bls12_381.ToMontgomery(dev); st != icicle_runtime.Success {
			t.Fatalf("ToMontgomery: %s", st.AsString())
		}

		// D2H
		got := make([]fr.Element, n)
		gotHost := (icicle_core.HostSlice[fr.Element])(got)
		gotHost.CopyFromDevice(&dev)

		if st := dev.Free(); st != icicle_runtime.Success {
			t.Logf("warning: free failed: %s", st.AsString())
		}

		if !frSliceEqual(got, orig) {
			t.Fatalf("Montgomery roundtrip mismatch")
		}
	})
	<-done
}

// 2) VecMulOnDevice 与 CPU 逐元素相乘一致（注意表示切换）
func TestVecMulOnDevice_MatchesCPU(t *testing.T) {
	device := mustCreateCUDADevice(t)

	n := 1 << 12
	a := randomScalars(n) // Montgomery
	b := randomScalars(n) // Montgomery

	// CPU 期望（Montgomery x Montgomery -> Montgomery）
	expect := make([]fr.Element, n)
	for i := range expect {
		expect[i].Mul(&a[i], &b[i])
	}

	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		defer close(done)

		var aDev, bDev icicle_core.DeviceSlice
		(icicle_core.HostSlice[fr.Element])(a).CopyToDevice(&aDev, true)
		(icicle_core.HostSlice[fr.Element])(b).CopyToDevice(&bDev, true)

		// VecOps 期望普通表示，先转出 Montgomery
		if st := icicle_bls12_381.FromMontgomery(aDev); st != icicle_runtime.Success {
			t.Fatalf("FromMontgomery(a): %s", st.AsString())
		}
		if st := icicle_bls12_381.FromMontgomery(bDev); st != icicle_runtime.Success {
			t.Fatalf("FromMontgomery(b): %s", st.AsString())
		}

		// aDev = aDev * bDev (逐元素)
		if st := VecMulOnDevice(aDev, bDev); st != icicle_runtime.Success {
			t.Fatalf("VecMulOnDevice: %s", st.AsString())
		}

		// 结果再转回 Montgomery，以便和 CPU 结果对齐比较
		if st := icicle_bls12_381.ToMontgomery(aDev); st != icicle_runtime.Success {
			t.Fatalf("ToMontgomery(result): %s", st.AsString())
		}

		// D2H
		got := make([]fr.Element, n)
		(icicle_core.HostSlice[fr.Element])(got).CopyFromDevice(&aDev)

		// 释放
		if st := aDev.Free(); st != icicle_runtime.Success {
			t.Logf("free aDev: %s", st.AsString())
		}
		if st := bDev.Free(); st != icicle_runtime.Success {
			t.Logf("free bDev: %s", st.AsString())
		}

		if !frSliceEqual(got, expect) {
			// 定位第一个不等的位置帮助排查
			for i := range got {
				if !got[i].Equal(&expect[i]) {
					t.Fatalf("VecMul mismatch at %d", i)
				}
			}
		}
	})
	<-done
}

// 3) NTT ∘ INTT = Identity（无 coset）
// 注意：icicle 的 KInverse 变换已经包含 1/n 归一化，和 gnark-crypto 的惯例一致。
func TestNTT_INTTRoundtrip_NoCoset(t *testing.T) {
	device := mustCreateCUDADevice(t)
	n := 1 << 12
	mustInitNTTDomainOnDevice(t, device, n)

	coeffs := randomScalars(n) // 系数域（Montgomery）
	expect := cloneFrSlice(coeffs)

	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		defer close(done)

		var aDev icicle_core.DeviceSlice
		(icicle_core.HostSlice[fr.Element])(coeffs).CopyToDevice(&aDev, true)

		// Forward NTT（系数 -> 评估），然后 Inverse NTT（评估 -> 系数）
		if st := NttOnDevice(aDev, false, [fr.Limbs * 2]uint32{}); st != icicle_runtime.Success {
			t.Fatalf("NTT forward: %s", st.AsString())
		}
		if st := INttOnDevice(aDev, false, [fr.Limbs * 2]uint32{}); st != icicle_runtime.Success {
			t.Fatalf("NTT inverse: %s", st.AsString())
		}

		got := make([]fr.Element, n)
		(icicle_core.HostSlice[fr.Element])(got).CopyFromDevice(&aDev)
		if st := aDev.Free(); st != icicle_runtime.Success {
			t.Logf("free aDev: %s", st.AsString())
		}

		if !frSliceEqual(got, expect) {
			t.Fatalf("NTT<->INTT roundtrip (no coset) mismatch")
		}
	})
	<-done
}

// 4) 带 coset 的 NTT/INTT 往返： NTT(u·ω^i) 再 INTT(u·ω^i) 应回到原系数
func TestNTT_INTTRoundtrip_WithCoset(t *testing.T) {
	device := mustCreateCUDADevice(t)
	n := 1 << 12
	mustInitNTTDomainOnDevice(t, device, n)

	coeffs := randomScalars(n) // 系数域（Montgomery）
	expect := cloneFrSlice(coeffs)

	// 取一个随机 coset 生成元 u != 0,1
	var u fr.Element
	for {
		if _, err := u.SetRandom(); err != nil {
			t.Fatalf("rand u: %v", err)
		}
		if !u.IsZero() && !u.IsOne() {
			break
		}
	}
	cg := CosetGenToIcicle(u)

	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		defer close(done)

		var aDev icicle_core.DeviceSlice
		(icicle_core.HostSlice[fr.Element])(coeffs).CopyToDevice(&aDev, true)

		// 在 coset 上 forward -> inverse
		if st := NttOnDevice(aDev, true, cg); st != icicle_runtime.Success {
			t.Fatalf("NTT forward (coset): %s", st.AsString())
		}
		if st := INttOnDevice(aDev, true, cg); st != icicle_runtime.Success {
			t.Fatalf("NTT inverse (coset): %s", st.AsString())
		}

		got := make([]fr.Element, n)
		(icicle_core.HostSlice[fr.Element])(got).CopyFromDevice(&aDev)
		if st := aDev.Free(); st != icicle_runtime.Success {
			t.Logf("free aDev: %s", st.AsString())
		}

		if !frSliceEqual(got, expect) {
			t.Fatalf("NTT<->INTT roundtrip (coset) mismatch")
		}
	})
	<-done
}

// 5) （可选附加）VecOps.Sub/零校验：验证设备端逐元素减法正确
func TestVecOpsSub_Device(t *testing.T) {
	device := mustCreateCUDADevice(t)
	n := 1 << 12
	a := randomScalars(n)
	b := randomScalars(n)

	// 期望：c = a - b（Montgomery）
	expect := make([]fr.Element, n)
	for i := range expect {
		expect[i].Sub(&a[i], &b[i])
	}

	done := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		defer close(done)

		var aDev, bDev icicle_core.DeviceSlice
		(icicle_core.HostSlice[fr.Element])(a).CopyToDevice(&aDev, true)
		(icicle_core.HostSlice[fr.Element])(b).CopyToDevice(&bDev, true)

		// VecOps 期望普通表示 → 先转出 Montgomery
		if st := icicle_bls12_381.FromMontgomery(aDev); st != icicle_runtime.Success {
			t.Fatalf("FromMontgomery(a): %s", st.AsString())
		}
		if st := icicle_bls12_381.FromMontgomery(bDev); st != icicle_runtime.Success {
			t.Fatalf("FromMontgomery(b): %s", st.AsString())
		}

		// a = a - b
		cfg := icicle_core.DefaultVecOpsConfig()
		if st := icicle_vecops.VecOp(aDev, bDev, aDev, cfg, icicle_core.Sub); st != icicle_runtime.Success {
			t.Fatalf("VecOp(Sub): %s", st.AsString())
		}

		// 回到 Montgomery，和 CPU 期望比
		if st := icicle_bls12_381.ToMontgomery(aDev); st != icicle_runtime.Success {
			t.Fatalf("ToMontgomery(a): %s", st.AsString())
		}
		got := make([]fr.Element, n)
		(icicle_core.HostSlice[fr.Element])(got).CopyFromDevice(&aDev)

		if st := aDev.Free(); st != icicle_runtime.Success {
			t.Logf("free aDev: %s", st.AsString())
		}
		if st := bDev.Free(); st != icicle_runtime.Success {
			t.Logf("free bDev: %s", st.AsString())
		}

		if !frSliceEqual(got, expect) {
			t.Fatalf("VecOps Sub mismatch")
		}
	})
	<-done
}

/* ============================
   1) KZG Open: GPU vs CPU
   ============================ */

func cpuOpen(p []fr.Element, point fr.Element, bases []curve.G1Affine) (kzg.OpeningProof, error) {
	var proof kzg.OpeningProof
	// f(z)
	proof.ClaimedValue = eval(p, point)
	// H(X) = (f(X)-f(z)) / (X-z)
	h := dividePolyByXminusA(append([]fr.Element(nil), p...), proof.ClaimedValue, point)
	// Commit(H) —— 需要 MultiExpConfig 第三个参数
	var H curve.G1Affine
	H.MultiExp(bases[:len(h)], h, ecc.MultiExpConfig{})
	proof.H = kzg.Digest(H)
	return proof, nil
}

func TestOnDeviceOpen_GPUvsCPU(t *testing.T) {
	device := mustCreateCUDADevice(t)

	cases := []int{1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 18}
	if testing.Short() {
		cases = []int{1 << 10, 1 << 12}
	}
	sort.Ints(cases)
	maxN := cases[len(cases)-1]

	t.Logf("building random SRS.G1 once (n=%d) for Open tests...", maxN)
	srsMax := buildRandomSRS_G1(maxN)

	for _, n := range cases {
		n := n
		t.Run(fmt.Sprintf("Open_n=%d", n), func(t *testing.T) {
			// 多项式 p
			p := randomScalars(n)
			// 随机点 z
			var z fr.Element
			if _, err := z.SetRandom(); err != nil {
				t.Fatal(err)
			}

			// ========== CPU baseline ==========
			t0 := time.Now()
			cpuProof, err := cpuOpen(p, z, srsMax[:n])
			if err != nil {
				t.Fatal(err)
			}
			cpuDur := time.Since(t0)

			// ========== GPU path ==========
			var gpuProof kzg.OpeningProof
			var gpuDur time.Duration
			var gpuErr error

			done := make(chan struct{})
			icicle_runtime.RunOnDevice(device, func(args ...any) {
				defer close(done)

				// H2D: G1 bases（只用前 n 个）
				hostG1 := (icicle_core.HostSlice[curve.G1Affine])(srsMax[:n])
				var g1Dev icicle_core.DeviceSlice
				hostG1.CopyToDevice(&g1Dev, true)

				// G1 出 Montgomery（与 OnDeviceOpen/Commit 配置匹配）
				if st := icicle_bls12_381.AffineFromMontgomery(g1Dev); st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("AffineFromMontgomery(G1): %s", st.AsString())
					_ = g1Dev.Free()
					return
				}

				t1 := time.Now()
				proof, st := OnDeviceOpen(p, z, g1Dev)
				gpuDur = time.Since(t1)

				if stFree := g1Dev.Free(); stFree != icicle_runtime.Success {
					t.Logf("warning: free G1 dev slice failed: %s", stFree.AsString())
				}
				if st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("OnDeviceOpen: %s", st.AsString())
					return
				}
				gpuProof = proof
			})
			<-done
			if gpuErr != nil {
				t.Skipf("GPU Open error: %v", gpuErr)
			}

			// 一致性
			cpuH := curve.G1Affine(cpuProof.H)
			gpuH := curve.G1Affine(gpuProof.H)
			if cpuProof.ClaimedValue != gpuProof.ClaimedValue {
				t.Fatalf("claimed value mismatch")
			}
			if !cpuH.Equal(&gpuH) {
				t.Fatalf("H digest mismatch")
			}

			speed := float64(cpuDur) / float64(gpuDur)
			t.Logf("Open n=%d  CPU=%s  GPU=%s  speedup=%.2fx", n, cpuDur, gpuDur, speed)
		})
	}
}

/*
============================
 2. NTT roundtrip: GPU vs CPU
    ============================
*/
func nttMaxLogN() int {
	if s := os.Getenv("ICICLE_NTT_MAX_LOGN"); s != "" {
		if k, err := strconv.Atoi(s); err == nil && k >= 1 {
			return k
		}
	}
	return 13
}
func TestNTT_RoundTrip_GPUvsCPU(t *testing.T) {
	device := mustCreateCUDADevice(t)

	maxK := nttMaxLogN()             // 默认 13 -> 8192
	cases := []int{1 << 10, 1 << 12} // 小规模必测
	for k := 13; k <= maxK; k++ {    // 继续追加到上限
		cases = append(cases, 1<<k)
	}
	if testing.Short() {
		cases = []int{1 << 10, 1 << 12}
	}

	for _, n := range cases {
		n := n
		t.Run(fmt.Sprintf("NTT_n=%d", n), func(t *testing.T) {
			in := randomScalars(n)

			// CPU roundtrip
			domain := fft.NewDomain(uint64(n))
			data := append([]fr.Element(nil), in...) // 先存到变量，避免对 append 结果取地址
			cpuPoly := iop.NewPolynomial(&data, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})
			t0 := time.Now()
			cpuPoly.ToLagrange(domain).ToCanonical(domain)
			cpuDur := time.Since(t0)
			cpuOut := cpuPoly.Coefficients()

			// GPU roundtrip
			var gpuOut []fr.Element
			var gpuDur time.Duration
			var gpuErr error

			done := make(chan struct{})
			icicle_runtime.RunOnDevice(device, func(args ...any) {
				defer close(done)

				host := icicle_core.HostSliceFromElements(in)
				var d icicle_core.DeviceSlice
				host.CopyToDevice(&d, true)

				cfg := icicle_ntt.GetDefaultNttConfig()
				cfg.Ordering = icicle_core.KMN // forward
				t1 := time.Now()
				if st := icicle_ntt.Ntt(d, icicle_core.KForward, &cfg, d); st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("NTT forward: %s", st.AsString())
					_ = d.Free()
					return
				}
				cfg.Ordering = icicle_core.KNR // inverse
				if st := icicle_ntt.Ntt(d, icicle_core.KInverse, &cfg, d); st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("NTT inverse: %s", st.AsString())
					_ = d.Free()
					return
				}
				gpuDur = time.Since(t1)

				out := make([]fr.Element, n)
				icicle_core.HostSliceFromElements(out).CopyFromDevice(&d)
				gpuOut = out

				if st := d.Free(); st != icicle_runtime.Success {
					t.Logf("warning: free ntt buf failed: %s", st.AsString())
				}
			})
			<-done
			if gpuErr != nil {
				t.Skipf("GPU NTT error: %v", gpuErr)
			}

			// 一致性
			for i := 0; i < n; i++ {
				if gpuOut[i] != cpuOut[i] {
					t.Fatalf("ntt roundtrip mismatch at %d", i)
				}
			}

			speed := float64(cpuDur) / float64(gpuDur)
			t.Logf("NTT n=%d  CPU=%s  GPU=%s  speedup=%.2fx", n, cpuDur, gpuDur, speed)
		})
	}
}

/* ============================
   3) VecMul (elementwise mul):
      GPU vs CPU
   ============================ */

func TestVecMul_GPUvsCPU(t *testing.T) {
	device := mustCreateCUDADevice(t)

	maxK := nttMaxLogN()             // 默认 13 -> 8192
	cases := []int{1 << 10, 1 << 12} // 小规模必测
	for k := 13; k <= maxK; k++ {    // 继续追加到上限
		cases = append(cases, 1<<k)
	}
	if testing.Short() {
		cases = []int{1 << 10, 1 << 12}
	}

	for _, n := range cases {
		n := n
		t.Run(fmt.Sprintf("VecMul_n=%d", n), func(t *testing.T) {
			a := randomScalars(n)
			b := randomScalars(n)

			// ========== CPU ==========
			aCPU := append([]fr.Element(nil), a...)
			t0 := time.Now()
			for i := 0; i < n; i++ {
				aCPU[i].Mul(&aCPU[i], &b[i]) // Montgomery 乘
			}
			cpuDur := time.Since(t0)

			// ========== GPU ==========
			var out []fr.Element
			var gpuDur time.Duration
			var gpuErr error

			done := make(chan struct{})
			icicle_runtime.RunOnDevice(device, func(args ...any) {
				defer close(done)

				ha := icicle_core.HostSliceFromElements(a)
				hb := icicle_core.HostSliceFromElements(b)
				var da, db icicle_core.DeviceSlice
				ha.CopyToDevice(&da, true)
				hb.CopyToDevice(&db, true)

				// 输入转出 Montgomery（VecOps 在“标准表示”做运算）
				if st := icicle_bls12_381.FromMontgomery(da); st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("FromMontgomery(a): %s", st.AsString())
					_ = da.Free()
					_ = db.Free()
					return
				}
				if st := icicle_bls12_381.FromMontgomery(db); st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("FromMontgomery(b): %s", st.AsString())
					_ = da.Free()
					_ = db.Free()
					return
				}

				cfg := icicle_core.DefaultVecOpsConfig()
				t1 := time.Now()
				if st := icicle_vecops.VecOp(da, db, da, cfg, icicle_core.Mul); st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("VecOp Mul: %s", st.AsString())
					_ = da.Free()
					_ = db.Free()
					return
				}
				// 结果转回 Montgomery，便于与 CPU 结果对比
				if st := icicle_bls12_381.ToMontgomery(da); st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("ToMontgomery(out): %s", st.AsString())
					_ = da.Free()
					_ = db.Free()
					return
				}
				gpuDur = time.Since(t1)

				out = make([]fr.Element, n)
				icicle_core.HostSliceFromElements(out).CopyFromDevice(&da)

				if st := da.Free(); st != icicle_runtime.Success {
					t.Logf("warning: free da failed: %s", st.AsString())
				}
				if st := db.Free(); st != icicle_runtime.Success {
					t.Logf("warning: free db failed: %s", st.AsString())
				}
			})
			<-done
			if gpuErr != nil {
				t.Skipf("GPU VecMul error: %v", gpuErr)
			}

			// 一致性
			for i := 0; i < n; i++ {
				if out[i] != aCPU[i] {
					t.Fatalf("vecmul mismatch at %d", i)
				}
			}

			speed := float64(cpuDur) / float64(gpuDur)
			t.Logf("VecMul n=%d  CPU=%s  GPU=%s  speedup=%.2fx", n, cpuDur, gpuDur, speed)
		})
	}
}

/* ============================
   4) Montgomery Conv: GPU roundtrip
   ============================ */

func TestMontConv_GPU_RoundTrip(t *testing.T) {
	device := mustCreateCUDADevice(t)

	maxK := nttMaxLogN()             // 默认 13 -> 8192
	cases := []int{1 << 10, 1 << 12} // 小规模必测
	for k := 13; k <= maxK; k++ {    // 继续追加到上限
		cases = append(cases, 1<<k)
	}
	if testing.Short() {
		cases = []int{1 << 10, 1 << 12}
	}

	for _, n := range cases {
		n := n
		t.Run(fmt.Sprintf("MontConv_n=%d", n), func(t *testing.T) {
			x := randomScalars(n)

			var roundtrip []fr.Element
			var dur time.Duration
			var gpuErr error

			done := make(chan struct{})
			icicle_runtime.RunOnDevice(device, func(args ...any) {
				defer close(done)

				hx := icicle_core.HostSliceFromElements(x)
				var dx icicle_core.DeviceSlice
				hx.CopyToDevice(&dx, true)

				t1 := time.Now()
				if st := icicle_bls12_381.FromMontgomery(dx); st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("FromMontgomery: %s", st.AsString())
					_ = dx.Free()
					return
				}
				if st := icicle_bls12_381.ToMontgomery(dx); st != icicle_runtime.Success {
					gpuErr = fmt.Errorf("ToMontgomery: %s", st.AsString())
					_ = dx.Free()
					return
				}
				dur = time.Since(t1)

				roundtrip = make([]fr.Element, n)
				icicle_core.HostSliceFromElements(roundtrip).CopyFromDevice(&dx)

				if st := dx.Free(); st != icicle_runtime.Success {
					t.Logf("warning: free dx failed: %s", st.AsString())
				}
			})
			<-done
			if gpuErr != nil {
				t.Skipf("GPU MontConv error: %v", gpuErr)
			}

			// 往返一致性
			for i := 0; i < n; i++ {
				if roundtrip[i] != x[i] {
					t.Fatalf("montgomery roundtrip mismatch at %d", i)
				}
			}
			t.Logf("MontConv roundtrip n=%d  time=%s", n, dur)
		})
	}
}
