package eonark

import (
	"github.com/consensys/gnark/backend"
	plonkbls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bls12-381"

	"github.com/eon-protocol/eonark/gpu"
)

func Prove(spr *cs.SparseR1CS, pk *plonkbls12381.ProvingKey, w witness.Witness, opts ...backend.ProverOption) (*plonkbls12381.Proof, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, err
	}

	if opt.Accelerator == "icicle" && gpu.HasIcicle {
		gpk := &gpu.ProvingKey{
			Kzg:         pk.Kzg,
			KzgLagrange: pk.KzgLagrange,
			Vk:          pk.Vk,
		}
		return gpu.Prove(spr, gpk, w, opts...)
	}

	return prove(spr, pk, w, opts...)
}
