//go:build icicle

package gpu

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	plonkbls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"

	"github.com/ingonyama-zk/gnark-crypto/ecc/bw6-633/fr"
	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

type deviceInfo struct {
	Device   icicle_runtime.Device
	G1Device struct {
		G1         icicle_core.DeviceSlice
		G1Lagrange icicle_core.DeviceSlice
	}
	CosetBase [fr.Limbs * 2]uint32
}

// 同名结构，icicle 版多了 deviceInfo
type ProvingKey struct {
	Kzg         kzg.ProvingKey
	KzgLagrange kzg.ProvingKey
	Vk          *plonkbls12381.VerifyingKey
	deviceInfo  *deviceInfo
}

func WrapProvingKey(pk *plonkbls12381.ProvingKey) (*ProvingKey, error) {
	warmUpDevice()
	return &ProvingKey{
		Kzg:         pk.Kzg,
		KzgLagrange: pk.KzgLagrange,
		Vk:          pk.Vk,
	}, nil
}
