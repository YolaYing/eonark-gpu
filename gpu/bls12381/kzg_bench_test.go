// // package kzg_bls12_381

// // import (
// // 	"fmt"
// // 	"os"
// // 	"sort"
// // 	"strconv"
// // 	"strings"
// // 	"testing"
// // 	"time"

// // 	eon "github.com/eon-protocol/eonark"

// // 	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
// // 	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
// // 	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
// // )

// // func loadCKBench(b *testing.B, want int) kzg.ProvingKey {
// // 	b.Helper()
// // 	ck, _, err := eon.ReadProvingKey(want, want)
// // 	if err != nil {
// // 		b.Fatalf("ReadProvingKey(%d): %v", want, err)
// // 	}
// // 	return ck
// // }

// // func randPolyBench(b *testing.B, n int) []fr.Element {
// // 	b.Helper()
// // 	p := make([]fr.Element, n)
// // 	for i := 0; i < n; i++ {
// // 		if _, err := p[i].SetRandom(); err != nil {
// // 			b.Fatalf("rand: %v", err)
// // 		}
// // 	}
// // 	return p
// // }

// // func getenvInt(key string, def int) int {
// // 	if s := os.Getenv(key); s != "" {
// // 		if v, err := strconv.Atoi(s); err == nil && v > 0 {
// // 			return v
// // 		}
// // 	}
// // 	return def
// // }

// // func medianDur(xs []time.Duration) time.Duration {
// // 	ys := append([]time.Duration(nil), xs...)
// // 	sort.Slice(ys, func(i, j int) bool { return ys[i] < ys[j] })
// // 	n := len(ys)
// // 	if n == 0 {
// // 		return 0
// // 	}
// // 	if n%2 == 1 {
// // 		return ys[n/2]
// // 	}
// // 	return (ys[n/2-1] + ys[n/2]) / 2
// // }

// // func medianF(xs []float64) float64 {
// // 	ys := append([]float64(nil), xs...)
// // 	sort.Slice(ys, func(i, j int) bool { return ys[i] < ys[j] })
// // 	n := len(ys)
// // 	if n == 0 {
// // 		return 0
// // 	}
// // 	if n%2 == 1 {
// // 		return ys[n/2]
// // 	}
// // 	return (ys[n/2-1] + ys[n/2]) / 2
// // }

// // // 确保基准在 CUDA 上运行；若不可用则跳过 GPU 基准。
// // func ensureCUDAOrSkip(b *testing.B) {
// // 	b.Helper()
// // 	if os.Getenv("ICICLE_TEST_GPU") == "skip" {
// // 		b.Skip("skip GPU bench (ICICLE_TEST_GPU=skip)")
// // 	}
// // 	if err := ensureCUDA(); err != nil {
// // 		b.Skipf("ensureCUDA failed: %v", err)
// // 	}
// // 	// 注册的设备里需要包含 CUDA
// // 	if regs, st := icicle_runtime.GetRegisteredDevices(); st == icicle_runtime.Success {
// // 		joined := strings.ToUpper(strings.Join(regs, ","))
// // 		if !strings.Contains(joined, "CUDA") {
// // 			b.Skipf("CUDA backend not registered (registered=%v)", regs)
// // 		}
// // 	} else {
// // 		b.Skipf("GetRegisteredDevices failed: %s", st.AsString())
// // 	}
// // 	// 至少 1 张 CUDA 设备可见
// // 	if n, st := icicle_runtime.GetDeviceCount(); st != icicle_runtime.Success || n <= 0 {
// // 		if st != icicle_runtime.Success {
// // 			b.Skipf("GetDeviceCount failed: %s", st.AsString())
// // 		} else {
// // 			b.Skipf("no CUDA device visible (count=%d)", n)
// // 		}
// // 	}
// // 	// 活跃设备必须是 CUDA
// // 	if d, st := icicle_runtime.GetActiveDevice(); st == icicle_runtime.Success {
// // 		b.Logf("[ICICLE] active=%s avail=%v", d.GetDeviceType(), icicle_runtime.IsDeviceAvailable(d))
// // 		if !strings.EqualFold(d.GetDeviceType(), "CUDA") {
// // 			b.Skipf("active device is %q (expect CUDA)", d.GetDeviceType())
// // 		}
// // 	} else {
// // 		b.Skipf("GetActiveDevice failed: %s", st.AsString())
// // 	}
// // }

// // // 原有对比：整体 CPU vs GPU 用时（不拆通信/计算）
// // func Benchmark_OnDeviceCommit_vs_CPU(b *testing.B) {
// // 	sizes := []int{1 << 12, 1 << 14, 1 << 16, 1 << 18, 1 << 20}

// // 	for _, n := range sizes {
// // 		n := n

// // 		b.Run(fmt.Sprintf("CPU/n=%d", n), func(b *testing.B) {
// // 			ck := loadCKBench(b, n)
// // 			p := randPolyBench(b, n)
// // 			if _, err := kzg.Commit(p, ck); err != nil { // warmup
// // 				b.Fatalf("warmup cpu: %v", err)
// // 			}
// // 			b.ResetTimer()
// // 			for i := 0; i < b.N; i++ {
// // 				if _, err := kzg.Commit(p, ck); err != nil {
// // 					b.Fatalf("cpu: %v", err)
// // 				}
// // 			}
// // 		})

// // 		b.Run(fmt.Sprintf("GPU/n=%d", n), func(b *testing.B) {
// // 			ensureCUDAOrSkip(b)

// // 			ck := loadCKBench(b, n)
// // 			p := randPolyBench(b, n)
// // 			if _, err := OnDeviceCommit(p, ck.G1[:n]); err != nil { // warmup
// // 				b.Skipf("gpu warmup failed: %v", err)
// // 			}
// // 			b.ResetTimer()
// // 			for i := 0; i < b.N; i++ {
// // 				if _, err := OnDeviceCommit(p, ck.G1[:n]); err != nil {
// // 					b.Fatalf("gpu: %v", err)
// // 				}
// // 			}
// // 		})
// // 	}
// // }

// // // 带分解的 Profile（H2D 标量/H2D 基点/Kernel/总用时 + 带宽）
// // func Benchmark_OnDeviceCommit_Profiled(b *testing.B) {
// // 	ensureCUDAOrSkip(b)

// // 	reps := getenvInt("ICICLE_BENCH_REPS", 5)
// // 	if reps < 3 {
// // 		reps = 3
// // 	}

// // 	sizes := []int{1 << 12, 1 << 14, 1 << 16, 1 << 18, 1 << 20, 1 << 22}
// // 	for _, n := range sizes {
// // 		n := n

// // 		b.Run(fmt.Sprintf("GPUProfile/n=%d", n), func(b *testing.B) {
// // 			ck := loadCKBench(b, n)
// // 			p := randPolyBench(b, n)

// // 			// warmup（建立上下文、防止一次性初始化噪音）
// // 			if _, _, err := OnDeviceCommitProfiled(p, ck.G1[:n]); err != nil {
// // 				b.Skipf("gpu profiled warmup failed: %v", err)
// // 			}

// // 			h2ds := make([]time.Duration, 0, reps)
// // 			h2dp := make([]time.Duration, 0, reps)
// // 			kern := make([]time.Duration, 0, reps)
// // 			tots := make([]time.Duration, 0, reps)
// // 			bws := make([]float64, 0, reps)
// // 			bwp := make([]float64, 0, reps)

// // 			b.StopTimer()
// // 			for i := 0; i < reps; i++ {
// // 				_, tt, err := OnDeviceCommitProfiled(p, ck.G1[:n])
// // 				if err != nil {
// // 					b.Fatalf("gpu profiled run: %v", err)
// // 				}
// // 				h2ds = append(h2ds, tt.H2DScalars)
// // 				h2dp = append(h2dp, tt.H2DPoints)
// // 				kern = append(kern, tt.KernelMSM)
// // 				tots = append(tots, tt.Total)
// // 				bws = append(bws, tt.BWScalarsGBs)
// // 				bwp = append(bwp, tt.BWPointsGBs)
// // 			}
// // 			b.StartTimer()

// // 			mdH2DS := medianDur(h2ds)
// // 			mdH2DP := medianDur(h2dp)
// // 			mdKern := medianDur(kern)
// // 			mdTot := medianDur(tots)
// // 			mdBWS := medianF(bws)
// // 			mdBWP := medianF(bwp)

// // 			b.ReportMetric(float64(mdH2DS)/float64(time.Millisecond), "H2DScalars_ms/op")
// // 			b.ReportMetric(float64(mdH2DP)/float64(time.Millisecond), "H2DPoints_ms/op")
// // 			b.ReportMetric(float64(mdKern)/float64(time.Millisecond), "KernelMSM_ms/op")
// // 			b.ReportMetric(float64(mdTot)/float64(time.Millisecond), "Total_ms/op")
// // 			b.ReportMetric(mdBWS, "BWScalars_GBs")
// // 			b.ReportMetric(mdBWP, "BWPoints_GBs")

// // 			b.Logf("[n=%d] H2D scalars: %v (%.2f GB/s) | H2D points: %v (%.2f GB/s) | Kernel: %v | Total: %v",
// // 				n, mdH2DS, mdBWS, mdH2DP, mdBWP, mdKern, mdTot)
// // 		})
// // 	}
// // }

// package kzg_bls12_381

// import (
// 	"fmt"
// 	"os"
// 	"sort"
// 	"strconv"
// 	"strings"
// 	"testing"
// 	"time"

// 	eon "github.com/eon-protocol/eonark"

// 	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
// 	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
// 	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
// )

// func loadCKBench(b *testing.B, want int) kzg.ProvingKey {
// 	b.Helper()
// 	ck, _, err := eon.ReadProvingKey(want, want)
// 	if err != nil {
// 		b.Fatalf("ReadProvingKey(%d): %v", want, err)
// 	}
// 	return ck
// }

// func randPolyBench(b *testing.B, n int) []fr.Element {
// 	b.Helper()
// 	p := make([]fr.Element, n)
// 	for i := 0; i < n; i++ {
// 		if _, err := p[i].SetRandom(); err != nil {
// 			b.Fatalf("rand: %v", err)
// 		}
// 	}
// 	return p
// }

// func getenvInt(key string, def int) int {
// 	if s := os.Getenv(key); s != "" {
// 		if v, err := strconv.Atoi(s); err == nil && v > 0 {
// 			return v
// 		}
// 	}
// 	return def
// }

// func medianDur(xs []time.Duration) time.Duration {
// 	ys := append([]time.Duration(nil), xs...)
// 	sort.Slice(ys, func(i, j int) bool { return ys[i] < ys[j] })
// 	n := len(ys)
// 	if n == 0 {
// 		return 0
// 	}
// 	if n%2 == 1 {
// 		return ys[n/2]
// 	}
// 	return (ys[n/2-1] + ys[n/2]) / 2
// }

// func medianF(xs []float64) float64 {
// 	ys := append([]float64(nil), xs...)
// 	sort.Slice(ys, func(i, j int) bool { return ys[i] < ys[j] })
// 	n := len(ys)
// 	if n == 0 {
// 		return 0
// 	}
// 	if n%2 == 1 {
// 		return ys[n/2]
// 	}
// 	return (ys[n/2-1] + ys[n/2]) / 2
// }

// // 确保基准在 CUDA 上运行；若不可用则跳过 GPU 基准。
// func ensureCUDAOrSkip(b *testing.B) {
// 	b.Helper()
// 	if os.Getenv("ICICLE_TEST_GPU") == "skip" {
// 		b.Skip("skip GPU bench (ICICLE_TEST_GPU=skip)")
// 	}
// 	if err := ensureCUDAOnce(); err != nil {
// 		b.Skipf("ensureCUDA failed: %v", err)
// 	}
// 	// 注册的设备里需要包含 CUDA
// 	if regs, st := icicle_runtime.GetRegisteredDevices(); st == icicle_runtime.Success {
// 		joined := strings.ToUpper(strings.Join(regs, ","))
// 		if !strings.Contains(joined, "CUDA") {
// 			b.Skipf("CUDA backend not registered (registered=%v)", regs)
// 		}
// 	} else {
// 		b.Skipf("GetRegisteredDevices failed: %s", st.AsString())
// 	}
// 	// 至少 1 张 CUDA 设备可见
// 	if n, st := icicle_runtime.GetDeviceCount(); st != icicle_runtime.Success || n <= 0 {
// 		if st != icicle_runtime.Success {
// 			b.Skipf("GetDeviceCount failed: %s", st.AsString())
// 		} else {
// 			b.Skipf("no CUDA device visible (count=%d)", n)
// 		}
// 	}
// 	// 活跃设备必须是 CUDA
// 	if d, st := icicle_runtime.GetActiveDevice(); st == icicle_runtime.Success {
// 		b.Logf("[ICICLE] active=%s avail=%v", d.GetDeviceType(), icicle_runtime.IsDeviceAvailable(d))
// 		if !strings.EqualFold(d.GetDeviceType(), "CUDA") {
// 			b.Skipf("active device is %q (expect CUDA)", d.GetDeviceType())
// 		}
// 	} else {
// 		b.Skipf("GetActiveDevice failed: %s", st.AsString())
// 	}
// }

// // 原有对比：整体 CPU vs GPU 用时（不拆通信/计算）
// func Benchmark_OnDeviceCommit_vs_CPU(b *testing.B) {
// 	sizes := []int{1 << 12, 1 << 14, 1 << 16, 1 << 18, 1 << 20}

// 	for _, n := range sizes {
// 		n := n

// 		b.Run(fmt.Sprintf("CPU/n=%d", n), func(b *testing.B) {
// 			ck := loadCKBench(b, n)
// 			p := randPolyBench(b, n)
// 			if _, err := kzg.Commit(p, ck); err != nil { // warmup
// 				b.Fatalf("warmup cpu: %v", err)
// 			}
// 			b.ResetTimer()
// 			for i := 0; i < b.N; i++ {
// 				if _, err := kzg.Commit(p, ck); err != nil {
// 					b.Fatalf("cpu: %v", err)
// 				}
// 			}
// 		})

// 		b.Run(fmt.Sprintf("GPU/n=%d", n), func(b *testing.B) {
// 			ensureCUDAOrSkip(b)
// 			ck := loadCKBench(b, n)
// 			p := randPolyBench(b, n)
// 			if _, err := OnDeviceCommit(p, ck.G1[:n]); err != nil { // warmup
// 				b.Skipf("gpu warmup failed: %v", err)
// 			}
// 			b.ResetTimer()
// 			for i := 0; i < b.N; i++ {
// 				if _, err := OnDeviceCommit(p, ck.G1[:n]); err != nil {
// 					b.Fatalf("gpu: %v", err)
// 				}
// 			}
// 		})
// 	}
// }

// // 带分解的 Profile（H2D 标量/H2D 基点/Kernel/总用时 + 带宽）
// func Benchmark_OnDeviceCommit_Profiled(b *testing.B) {
// 	ensureCUDAOrSkip(b)

// 	reps := getenvInt("ICICLE_BENCH_REPS", 5)
// 	if reps < 3 {
// 		reps = 3
// 	}

// 	sizes := []int{1 << 12, 1 << 14, 1 << 16, 1 << 18, 1 << 20, 1 << 22, 1 << 24}
// 	for _, n := range sizes {
// 		n := n

// 		b.Run(fmt.Sprintf("GPUProfile/n=%d", n), func(b *testing.B) {
// 			ck := loadCKBench(b, n)
// 			p := randPolyBench(b, n)

// 			// warmup（建立上下文、防止一次性初始化噪音）
// 			if _, _, err := OnDeviceCommitProfiled(p, ck.G1[:n]); err != nil {
// 				b.Skipf("gpu profiled warmup failed: %v", err)
// 			}

// 			h2ds := make([]time.Duration, 0, reps)
// 			h2dp := make([]time.Duration, 0, reps)
// 			kern := make([]time.Duration, 0, reps)
// 			tots := make([]time.Duration, 0, reps)
// 			bws := make([]float64, 0, reps)
// 			bwp := make([]float64, 0, reps)

// 			b.StopTimer()
// 			for i := 0; i < reps; i++ {
// 				_, tt, err := OnDeviceCommitProfiled(p, ck.G1[:n])
// 				if err != nil {
// 					b.Fatalf("gpu profiled run: %v", err)
// 				}
// 				h2ds = append(h2ds, tt.H2DScalars)
// 				h2dp = append(h2dp, tt.H2DPoints)
// 				kern = append(kern, tt.KernelMSM)
// 				tots = append(tots, tt.Total)
// 				bws = append(bws, tt.BWScalarsGBs)
// 				bwp = append(bwp, tt.BWPointsGBs)
// 			}
// 			b.StartTimer()

// 			mdH2DS := medianDur(h2ds)
// 			mdH2DP := medianDur(h2dp)
// 			mdKern := medianDur(kern)
// 			mdTot := medianDur(tots)
// 			mdBWS := medianF(bws)
// 			mdBWP := medianF(bwp)

// 			b.ReportMetric(float64(mdH2DS)/float64(time.Millisecond), "H2DScalars_ms/op")
// 			b.ReportMetric(float64(mdH2DP)/float64(time.Millisecond), "H2DPoints_ms/op")
// 			b.ReportMetric(float64(mdKern)/float64(time.Millisecond), "KernelMSM_ms/op")
// 			b.ReportMetric(float64(mdTot)/float64(time.Millisecond), "Total_ms/op")
// 			b.ReportMetric(mdBWS, "BWScalars_GBs")
// 			b.ReportMetric(mdBWP, "BWPoints_GBs")

//				b.Logf("[n=%d] H2D scalars: %v (%.2f GB/s) | H2D points: %v (%.2f GB/s) | Kernel: %v | Total: %v",
//					n, mdH2DS, mdBWS, mdH2DP, mdBWP, mdKern, mdTot)
//			})
//		}
//	}
package kzg_bls12_381

// import (
// 	"flag"
// 	"fmt"
// 	"os"
// 	"sort"
// 	"strconv"
// 	"strings"
// 	"testing"
// 	"time"

// 	eon "github.com/eon-protocol/eonark"

// 	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
// 	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
// 	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
// )

// var benchDeviceFlag = flag.String("bench.device", "auto", "which device to run benches on: cpu|gpu|auto")

// func benchDevice() string {
// 	// 允许用环境变量覆盖（可选）
// 	if v := os.Getenv("BENCH_DEVICE"); v != "" {
// 		return strings.ToLower(v)
// 	}
// 	return strings.ToLower(*benchDeviceFlag)
// }

// func loadCKBench(b *testing.B, want int) kzg.ProvingKey {
// 	b.Helper()
// 	ck, _, err := eon.ReadProvingKey(want, want)
// 	if err != nil {
// 		b.Fatalf("ReadProvingKey(%d): %v", want, err)
// 	}
// 	return ck
// }

// func randPolyBench(b *testing.B, n int) []fr.Element {
// 	b.Helper()
// 	p := make([]fr.Element, n)
// 	for i := 0; i < n; i++ {
// 		if _, err := p[i].SetRandom(); err != nil {
// 			b.Fatalf("rand: %v", err)
// 		}
// 	}
// 	return p
// }

// func getenvInt(key string, def int) int {
// 	if s := os.Getenv(key); s != "" {
// 		if v, err := strconv.Atoi(s); err == nil && v > 0 {
// 			return v
// 		}
// 	}
// 	return def
// }

// func medianDur(xs []time.Duration) time.Duration {
// 	ys := append([]time.Duration(nil), xs...)
// 	sort.Slice(ys, func(i, j int) bool { return ys[i] < ys[j] })
// 	n := len(ys)
// 	if n == 0 {
// 		return 0
// 	}
// 	if n%2 == 1 {
// 		return ys[n/2]
// 	}
// 	return (ys[n/2-1] + ys[n/2]) / 2
// }

// func medianF(xs []float64) float64 {
// 	ys := append([]float64(nil), xs...)
// 	sort.Slice(ys, func(i, j int) bool { return ys[i] < ys[j] })
// 	n := len(ys)
// 	if n == 0 {
// 		return 0
// 	}
// 	if n%2 == 1 {
// 		return ys[n/2]
// 	}
// 	return (ys[n/2-1] + ys[n/2]) / 2
// }

// // 只在需要 GPU 的子基准里调用；若 CUDA 不可用则 Skip
// func ensureCUDAOrSkip(b *testing.B) {
// 	b.Helper()

// 	// 若明确指定了 cpu，就直接跳过
// 	if benchDevice() == "cpu" {
// 		b.Skip("bench.device=cpu (skip GPU benches)")
// 	}

// 	// 环境变量显式跳过
// 	if os.Getenv("ICICLE_TEST_GPU") == "skip" {
// 		b.Skip("skip GPU bench (ICICLE_TEST_GPU=skip)")
// 	}

// 	// 初始化一次全局 CUDA（来自 kzg.go）
// 	if err := ensureCUDAOnce(); err != nil {
// 		b.Skipf("ensureCUDA failed: %v", err)
// 	}
// 	// 把“当前线程”的活跃设备也绑到 CUDA（关键！bench 可能在新线程）
// 	if err := ensureCUDAOnThisThread(); err != nil {
// 		b.Skipf("ensureCUDAOnThisThread failed: %v", err)
// 	}

// 	// 注册的设备里需要包含 CUDA
// 	if regs, st := icicle_runtime.GetRegisteredDevices(); st == icicle_runtime.Success {
// 		joined := strings.ToUpper(strings.Join(regs, ","))
// 		if !strings.Contains(joined, "CUDA") {
// 			b.Skipf("CUDA backend not registered (registered=%v)", regs)
// 		}
// 	} else {
// 		b.Skipf("GetRegisteredDevices failed: %s", st.AsString())
// 	}

// 	// 至少 1 张 CUDA 设备可见
// 	if n, st := icicle_runtime.GetDeviceCount(); st != icicle_runtime.Success || n <= 0 {
// 		if st != icicle_runtime.Success {
// 			b.Skipf("GetDeviceCount failed: %s", st.AsString())
// 		} else {
// 			b.Skipf("no CUDA device visible (count=%d)", n)
// 		}
// 	}

// 	// 活跃设备必须是 CUDA
// 	if d, st := icicle_runtime.GetActiveDevice(); st == icicle_runtime.Success {
// 		b.Logf("[ICICLE] active=%s avail=%v", d.GetDeviceType(), icicle_runtime.IsDeviceAvailable(d))
// 		if !strings.EqualFold(d.GetDeviceType(), "CUDA") {
// 			b.Skipf("active device is %q (expect CUDA)", d.GetDeviceType())
// 		}
// 	} else {
// 		b.Skipf("GetActiveDevice failed: %s", st.AsString())
// 	}
// }

// // 整体 CPU vs GPU（根据 bench.device 选择性执行）
// func Benchmark_OnDeviceCommit_vs_CPU(b *testing.B) {
// 	sizes := []int{1 << 12, 1 << 14, 1 << 16, 1 << 18, 1 << 20, 1 << 22, 1 << 24}
// 	wantCPU := benchDevice() != "gpu" // auto/cpu -> 跑 CPU
// 	wantGPU := benchDevice() != "cpu" // auto/gpu -> 跑 GPU

// 	for _, n := range sizes {
// 		n := n

// 		if wantCPU {
// 			b.Run(fmt.Sprintf("CPU/n=%d", n), func(b *testing.B) {
// 				ck := loadCKBench(b, n)
// 				p := randPolyBench(b, n)
// 				if _, err := kzg.Commit(p, ck); err != nil { // warmup
// 					b.Fatalf("warmup cpu: %v", err)
// 				}
// 				b.ResetTimer()
// 				for i := 0; i < b.N; i++ {
// 					if _, err := kzg.Commit(p, ck); err != nil {
// 						b.Fatalf("cpu: %v", err)
// 					}
// 				}
// 			})
// 		}

// 		if wantGPU {
// 			b.Run(fmt.Sprintf("GPU/n=%d", n), func(b *testing.B) {
// 				ensureCUDAOrSkip(b)
// 				ck := loadCKBench(b, n)
// 				p := randPolyBench(b, n)
// 				if _, err := OnDeviceCommit(p, ck.G1[:n]); err != nil { // warmup
// 					b.Skipf("gpu warmup failed: %v", err)
// 				}
// 				b.ResetTimer()
// 				for i := 0; i < b.N; i++ {
// 					if _, err := OnDeviceCommit(p, ck.G1[:n]); err != nil {
// 						b.Fatalf("gpu: %v", err)
// 					}
// 				}
// 			})
// 		}
// 	}
// }

// // 仅 GPU 分解 Profile（若 bench.device=cpu 则直接 Skip）
// func Benchmark_OnDeviceCommit_Profiled(b *testing.B) {
// 	if benchDevice() == "cpu" {
// 		b.Skip("bench.device=cpu (skip GPU profiled bench)")
// 	}
// 	ensureCUDAOrSkip(b)

// 	reps := getenvInt("ICICLE_BENCH_REPS", 5)
// 	if reps < 3 {
// 		reps = 3
// 	}

// 	sizes := []int{1 << 12, 1 << 14, 1 << 16, 1 << 18, 1 << 20, 1 << 22, 1 << 24}
// 	for _, n := range sizes {
// 		n := n

// 		b.Run(fmt.Sprintf("GPUProfile/n=%d", n), func(b *testing.B) {
// 			ck := loadCKBench(b, n)
// 			p := randPolyBench(b, n)

// 			// warmup（建立上下文、防止一次性初始化噪音）
// 			if _, _, err := OnDeviceCommitProfiled(p, ck.G1[:n]); err != nil {
// 				b.Skipf("gpu profiled warmup failed: %v", err)
// 			}

// 			h2ds := make([]time.Duration, 0, reps)
// 			h2dp := make([]time.Duration, 0, reps)
// 			kern := make([]time.Duration, 0, reps)
// 			tots := make([]time.Duration, 0, reps)
// 			bws := make([]float64, 0, reps)
// 			bwp := make([]float64, 0, reps)

// 			b.StopTimer()
// 			for i := 0; i < reps; i++ {
// 				_, tt, err := OnDeviceCommitProfiled(p, ck.G1[:n])
// 				if err != nil {
// 					b.Fatalf("gpu profiled run: %v", err)
// 				}
// 				h2ds = append(h2ds, tt.H2DScalars)
// 				h2dp = append(h2dp, tt.H2DPoints)
// 				kern = append(kern, tt.KernelMSM)
// 				tots = append(tots, tt.Total)
// 				bws = append(bws, tt.BWScalarsGBs)
// 				bwp = append(bwp, tt.BWPointsGBs)
// 			}
// 			b.StartTimer()

// 			mdH2DS := medianDur(h2ds)
// 			mdH2DP := medianDur(h2dp)
// 			mdKern := medianDur(kern)
// 			mdTot := medianDur(tots)
// 			mdBWS := medianF(bws)
// 			mdBWP := medianF(bwp)

// 			b.ReportMetric(float64(mdH2DS)/float64(time.Millisecond), "H2DScalars_ms/op")
// 			b.ReportMetric(float64(mdH2DP)/float64(time.Millisecond), "H2DPoints_ms/op")
// 			b.ReportMetric(float64(mdKern)/float64(time.Millisecond), "KernelMSM_ms/op")
// 			b.ReportMetric(float64(mdTot)/float64(time.Millisecond), "Total_ms/op")
// 			b.ReportMetric(mdBWS, "BWScalars_GBs")
// 			b.ReportMetric(mdBWP, "BWPoints_GBs")

// 			b.Logf("[n=%d] H2D scalars: %v (%.2f GB/s) | H2D points: %v (%.2f GB/s) | Kernel: %v | Total: %v",
// 				n, mdH2DS, mdBWS, mdH2DP, mdBWP, mdKern, mdTot)
// 		})
// 	}
// }
