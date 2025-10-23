//go:build icicle

package gpu

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	plonkbls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

type deviceInfo struct {
	Device   icicle_runtime.Device
	G1Device struct {
		G1         icicle_core.DeviceSlice
		G1Lagrange icicle_core.DeviceSlice
	}
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
