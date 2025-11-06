//go:build icicle

package bls12_381_gpu

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	icore "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	ivec "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381/vecOps"
	irun "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

// ---------- helpers ----------

func cpuVecMul(a, b []fr.Element) []fr.Element {
	n := len(a)
	out := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		out[i].Mul(&a[i], &b[i]) // fr.Element 内部是 Mont 表示
	}
	return out
}

func equalElems(a, b []fr.Element) (bool, int) {
	if len(a) != len(b) {
		return false, -1
	}
	for i := range a {
		var d fr.Element
		d.Sub(&a[i], &b[i])
		if !d.IsZero() {
			return false, i
		}
	}
	return true, -1
}

// 在设备上做就地逐元素乘法：out <- a * b
// pre  = "none" 或 "from"（把输入从 Mont 转 非Mont）
// post = "none" 或 "to"   （把输出从 非Mont 转回 Mont）
func gpuVecMulDevice(a, b []fr.Element, pre, post string) ([]fr.Element, irun.EIcicleError) {
	// 1) host -> device
	hostA := icore.HostSliceFromElements(a)
	hostB := icore.HostSliceFromElements(b)

	var aDev, bDev icore.DeviceSlice
	hostA.CopyToDevice(&aDev, true)
	hostB.CopyToDevice(&bDev, true)
	defer aDev.Free()
	defer bDev.Free()

	// 2) 可选：把 Mont 输入转到 非Mont（若 vecOps 需要非Mont）
	if pre == "from" {
		if st := MontConvOnDevice(aDev, false /* FromMont */); st != irun.Success {
			return nil, st
		}
		if st := MontConvOnDevice(bDev, false); st != irun.Success {
			return nil, st
		}
	}

	// 3) 设备端逐元素乘法（写回 aDev）
	cfg := icore.DefaultVecOpsConfig()
	if st := ivec.VecOp(aDev, bDev, aDev, cfg, icore.Mul); st != irun.Success {
		return nil, st
	}

	// 4) 可选：把结果从 非Mont 转回 Mont，便于与 CPU(Mont) 基准比对
	if post == "to" {
		if st := MontConvOnDevice(aDev, true /* ToMont */); st != irun.Success {
			return nil, st
		}
	}

	// 5) device -> host
	out := make([]fr.Element, len(a))
	hostOut := icore.HostSliceFromElements(out)
	hostOut.CopyFromDevice(&aDev) // ← 注意：是 HostSlice 调用 CopyFromDevice

	return out, irun.Success
}

// ---------- test ----------

func TestVecOps_InputRepresentation_AutoDetect(t *testing.T) {
	// 构造确定性数据
	const n = 16
	a := make([]fr.Element, n)
	b := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		a[i].SetUint64(uint64(i + 1))   // 1,2,3,...
		b[i].SetUint64(uint64(2*i + 3)) // 3,5,7,...
	}
	// CPU(Mont) 基准
	expMont := cpuVecMul(a, b)

	// 路径1：直接用 Mont 输入，不做任何设备端转换
	gotDirect, st := gpuVecMulDevice(a, b, "none", "none")
	if st != irun.Success {
		t.Fatalf("gpu vec mul (direct) error: %s", st.AsString())
	}
	matchDirect, idxDirect := equalElems(gotDirect, expMont)

	// 路径2：先把输入从 Mont 转 非Mont，乘完再把结果转回 Mont
	gotRoundTrip, st := gpuVecMulDevice(a, b, "from", "to")
	if st != irun.Success {
		t.Fatalf("gpu vec mul (pre FromMont -> post ToMont) error: %s", st.AsString())
	}
	matchRoundTrip, idxRound := equalElems(gotRoundTrip, expMont)

	t.Logf("Direct(no-conv) match CPU? %v (first diff @ %d)", matchDirect, idxDirect)
	t.Logf("FromMont->Mul->ToMont match CPU? %v (first diff @ %d)", matchRoundTrip, idxRound)

	switch {
	case matchDirect && !matchRoundTrip:
		t.Log("Diagnosis: vecOps inputs appear to be MONTGOMERY form.")
	case !matchDirect && matchRoundTrip:
		t.Log("Diagnosis: vecOps inputs appear to be NON-MONTGOMERY (canonical) form.")
	case matchDirect && matchRoundTrip:
		t.Log("Diagnosis: both paths matched; vecOps may internally handle both representations.")
	default:
		t.Fatalf("Neither path matched CPU baseline; check device copies or conversion directions.")
	}
}
