package eonark

import (
	"fmt"
	"io"
	"log"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonkbls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/constraint"
	csbls12381 "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

type Pk struct {
	vk  Vk
	ccs csbls12381.SparseR1CS
}

func (me *Pk) Compile(circuit frontend.Circuit) error {
	ccs, err := frontend.Compile(FIELD, scs.NewBuilder, circuit)
	if err != nil {
		return err
	}
	nc := len(ccs.GetCommitments().CommitmentIndexes())
	if nc != 1 {
		return fmt.Errorf("number of commitments is %d not 1", nc)
	}
	spkc, spkl, err := read_proving_key(plonk.SRSSize(ccs))
	if err != nil {
		return err
	}
	ipk, _, err := plonk.Setup(ccs, &kzg.SRS{Pk: spkc, Vk: SRS_VK}, &kzg.SRS{Pk: spkl, Vk: SRS_VK})
	if err != nil {
		return err
	}
	return me.FromGnarkConstraintSystemAndProvingKey(ccs, ipk)
}

func (me *Pk) Vk() Vk {
	return me.vk
}

func (me *Pk) ToGnarkProvingKey() plonk.ProvingKey {
	spkc, spkl, err := read_proving_key(plonk.SRSSize(&me.ccs))
	if err != nil {
		log.Fatalln(err)
	}
	return &plonkbls12381.ProvingKey{
		Kzg:         spkc,
		KzgLagrange: spkl,
		Vk:          me.vk.ToGnarkVerifyingKey().(*plonkbls12381.VerifyingKey),
	}
}

func (me *Pk) ToGnarkConstraintSystem() constraint.ConstraintSystem {
	return &me.ccs
}

func (me *Pk) FromGnarkConstraintSystemAndProvingKey(ccs constraint.ConstraintSystem, pk plonk.ProvingKey) error {
	me.vk.FromGnarkVerifyingKey(pk.VerifyingKey().(*plonkbls12381.VerifyingKey))
	me.ccs = *ccs.(*csbls12381.SparseR1CS)
	return nil
}

func (me *Pk) FromGnarkConstraintSystemAndVerifyingKey(ccs constraint.ConstraintSystem, vk plonk.VerifyingKey) error {
	me.vk.FromGnarkVerifyingKey(vk)
	me.ccs = *ccs.(*csbls12381.SparseR1CS)
	return nil
}

func (me *Pk) Prove(assignment frontend.Circuit) ([4]fr.Element, []fr.Element, *Proof, error) {
	witness, err := frontend.NewWitness(assignment, FIELD)
	if err != nil {
		return [4]fr.Element{}, nil, nil, err
	}
	// gp, err := plonk.Prove(&me.ccs, me.ToGnarkProvingKey(), witness, OPT_PROVER)
	gp, err := prove(&me.ccs, me.ToGnarkProvingKey().(*plonkbls12381.ProvingKey), witness, OPT_PROVER)
	if err != nil {
		return [4]fr.Element{}, nil, nil, err
	}
	var proof Proof
	if err := proof.FromGnarkProof(gp); err != nil {
		return [4]fr.Element{}, nil, nil, err
	}
	vec := witness.Vector().(fr.Vector)
	return [4]fr.Element{vec[0], vec[1], vec[2], vec[3]}, vec[4:], &proof, nil
}

func (me *Pk) WriteTo(w io.Writer) (int64, error) {
	if n, err := me.vk.WriteTo(w); err != nil {
		return n, err
	} else {
		m, err := me.ccs.WriteTo(w)
		return m + n, err
	}
}

func (me *Pk) ReadFrom(r io.Reader) (int64, error) {
	if n, err := me.vk.ReadFrom(r); err != nil {
		return n, err
	} else {
		m, err := me.ccs.ReadFrom(r)
		return m + n, err
	}
}
