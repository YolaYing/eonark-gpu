//go:build !icicle

package gpu

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/backend"
	plonkbls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bls12-381"
)

const HasIcicle = false

type ProvingKey struct {
	Kzg         kzg.ProvingKey
	KzgLagrange kzg.ProvingKey
	Vk          *plonkbls12381.VerifyingKey
}

func Prove(_ *cs.SparseR1CS, _ *ProvingKey, _ witness.Witness, _ ...backend.ProverOption) (*plonkbls12381.Proof, error) {
	return nil, errors.New("icicle requested but program compiled without 'icicle' build tag")
}
