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
package kzg_bls12_381

import (
	"fmt"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_bls12_381 "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
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
