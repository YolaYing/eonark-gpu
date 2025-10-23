package kzg_bls12_381

import (
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_bls12_381 "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381"
	icicle_msm "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bls12381/msm"
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
