// Package recursion contains a PLONK verifier circuit that can verify proofs
// generated over multiple pairing-friendly curves.
// The code is parameterized by the scalar field FR and the elliptic-curve groups (G1, G2, GT).
// It supports Poseidon2-based transcript that matches the off-chain execution code (via FSInputs).
package recursion

import (
	"fmt"

	"github.com/eon-protocol/eonark/circuits/hasher"

	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	backend_plonk "github.com/consensys/gnark/backend/plonk"
	plonkbackend_bls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	plonkbackend_bls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	plonkbackend_bls24315 "github.com/consensys/gnark/backend/plonk/bls24-315"
	plonkbackend_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	plonkbackend_bw6761 "github.com/consensys/gnark/backend/plonk/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/commitments/kzg"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/std/selector"
)

// Proof is a typed PLONK proof of SNARK. Use [ValueOfProof] to initialize the
// witness from the native proof. Use [PlaceholderProof] to initialize the
// placeholder witness for compiling the circuit.
type Proof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {

	// Commitments to the solution vectors
	LRO [3]kzg.Commitment[G1El]

	// Commitment to Z, the permutation polynomial
	Z kzg.Commitment[G1El]

	// Commitments to h1, h2, h3 such that h = h1 + Xh2 + X**2h3 is the quotient polynomial
	H [3]kzg.Commitment[G1El]

	Bsb22Commitments []kzg.Commitment[G1El]

	// Batch opening proof of h1 + zeta*h2 + zeta**2h3, linearizedPolynomial, l, r, o, s1, s2, qCPrime
	BatchedProof kzg.BatchOpeningProof[FR, G1El]

	// Opening proof of Z at zeta*mu
	ZShiftedOpening kzg.OpeningProof[FR, G1El]
}

// G1 decomposition witness, G1EL cannot be decompose directly, so we use its decomposed version as extra witness
type G1Decomp struct{ XQ, XM, YQ, YM frontend.Variable }

// All inputs Poseidon2-FS needed
type FSInputs struct {
	CIDGamma, CIDBeta, CIDAlpha, CIDZeta frontend.Variable
	// VK
	S                  [3]G1Decomp
	Ql, Qr, Qm, Qo, Qk G1Decomp
	Qc                 []G1Decomp

	// Proof
	W   [3]G1Decomp // CW1,CW2,CW3
	BSB []G1Decomp  // set as 1 in vk.go
	Z   G1Decomp    // CPZ
	H   [3]G1Decomp // CH1,CH2,CH3

	Publics []frontend.Variable
}

// ValueOfProof returns the typed witness of the native proof. It returns an
// error if there is a mismatch between the type parameters and the provided
// native proof.
func ValueOfProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](proof backend_plonk.Proof) (Proof[FR, G1El, G2El], error) {
	var ret Proof[FR, G1El, G2El]
	var err error
	switch r := any(&ret).(type) {
	case *Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]:
		tProof, ok := proof.(*plonkbackend_bls12377.Proof)
		if !ok {
			return ret, fmt.Errorf("expected sw_bls12377.Proof, got %T", proof)
		}
		for i := range r.LRO {
			r.LRO[i], err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tProof.LRO[i])
			if err != nil {
				return ret, fmt.Errorf("commitment LRO[%d] value assignment: %w", i, err)
			}
		}
		r.Z, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tProof.Z)
		if err != nil {
			return ret, fmt.Errorf("commitment Z value assignment: %w", err)
		}
		for i := range r.H {
			r.H[i], err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tProof.H[i])
			if err != nil {
				return ret, fmt.Errorf("commitment H[%d] value assignment: %w", i, err)
			}
		}
		r.Bsb22Commitments = make([]kzg.Commitment[sw_bls12377.G1Affine], len(tProof.Bsb22Commitments))
		for i := range r.Bsb22Commitments {
			r.Bsb22Commitments[i], err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tProof.Bsb22Commitments[i])
			if err != nil {
				return ret, fmt.Errorf("bsb22 commitment %d value assignment: %w", i, err)
			}
		}
		// TODO: actually we compute the opening point later. Maybe we can precompute it here and later assert its correctness?
		r.BatchedProof, err = kzg.ValueOfBatchOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine](tProof.BatchedProof)
		if err != nil {
			return ret, fmt.Errorf("batch opening proof value assignment: %w", err)
		}
		r.ZShiftedOpening, err = kzg.ValueOfOpeningProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine](tProof.ZShiftedOpening)
		if err != nil {
			return ret, fmt.Errorf("z shifted opening proof value assignment: %w", err)
		}
	case *Proof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine]:
		tProof, ok := proof.(*plonkbackend_bls12381.Proof)
		if !ok {
			return ret, fmt.Errorf("expected sw_bls12381.Proof, got %T", proof)
		}
		for i := range r.LRO {
			r.LRO[i], err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tProof.LRO[i])
			if err != nil {
				return ret, fmt.Errorf("commitment LRO[%d] value assignment: %w", i, err)
			}
		}
		r.Z, err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tProof.Z)
		if err != nil {
			return ret, fmt.Errorf("commitment Z value assignment: %w", err)
		}
		for i := range r.H {
			r.H[i], err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tProof.H[i])
			if err != nil {
				return ret, fmt.Errorf("commitment H[%d] value assignment: %w", i, err)
			}
		}
		r.Bsb22Commitments = make([]kzg.Commitment[sw_bls12381.G1Affine], len(tProof.Bsb22Commitments))
		for i := range r.Bsb22Commitments {
			r.Bsb22Commitments[i], err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tProof.Bsb22Commitments[i])
			if err != nil {
				return ret, fmt.Errorf("bsb22 commitment %d value assignment: %w", i, err)
			}
		}
		// TODO: actually we compute the opening point later. Maybe we can precompute it here and later assert its correctness?
		r.BatchedProof, err = kzg.ValueOfBatchOpeningProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine](tProof.BatchedProof)
		if err != nil {
			return ret, fmt.Errorf("batch opening proof value assignment: %w", err)
		}
		r.ZShiftedOpening, err = kzg.ValueOfOpeningProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine](tProof.ZShiftedOpening)
		if err != nil {
			return ret, fmt.Errorf("z shifted opening proof value assignment: %w", err)
		}
	case *Proof[sw_bls24315.ScalarField, sw_bls24315.G1Affine, sw_bls24315.G2Affine]:
		tProof, ok := proof.(*plonkbackend_bls24315.Proof)
		if !ok {
			return ret, fmt.Errorf("expected sw_bls24315.Proof, got %T", proof)
		}
		for i := range r.LRO {
			r.LRO[i], err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tProof.LRO[i])
			if err != nil {
				return ret, fmt.Errorf("commitment LRO[%d] value assignment: %w", i, err)
			}
		}
		r.Z, err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tProof.Z)
		if err != nil {
			return ret, fmt.Errorf("commitment Z value assignment: %w", err)
		}
		for i := range r.H {
			r.H[i], err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tProof.H[i])
			if err != nil {
				return ret, fmt.Errorf("commitment H[%d] value assignment: %w", i, err)
			}
		}
		r.Bsb22Commitments = make([]kzg.Commitment[sw_bls24315.G1Affine], len(tProof.Bsb22Commitments))
		for i := range r.Bsb22Commitments {
			r.Bsb22Commitments[i], err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tProof.Bsb22Commitments[i])
			if err != nil {
				return ret, fmt.Errorf("bsb22 commitment %d value assignment: %w", i, err)
			}
		}
		// TODO: actually we compute the opening point later. Maybe we can precompute it here and later assert its correctness?
		r.BatchedProof, err = kzg.ValueOfBatchOpeningProof[sw_bls24315.ScalarField, sw_bls24315.G1Affine](tProof.BatchedProof)
		if err != nil {
			return ret, fmt.Errorf("batch opening proof value assignment: %w", err)
		}
		r.ZShiftedOpening, err = kzg.ValueOfOpeningProof[sw_bls24315.ScalarField, sw_bls24315.G1Affine](tProof.ZShiftedOpening)
		if err != nil {
			return ret, fmt.Errorf("z shifted opening proof value assignment: %w", err)
		}

	case *Proof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine]:
		tProof, ok := proof.(*plonkbackend_bw6761.Proof)
		if !ok {
			return ret, fmt.Errorf("expected sw_bls12377.Proof, got %T", proof)
		}
		for i := range r.LRO {
			r.LRO[i], err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tProof.LRO[i])
			if err != nil {
				return ret, fmt.Errorf("commitment LRO[%d] value assignment: %w", i, err)
			}
		}
		r.Z, err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tProof.Z)
		if err != nil {
			return ret, fmt.Errorf("commitment Z value assignment: %w", err)
		}
		for i := range r.H {
			r.H[i], err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tProof.H[i])
			if err != nil {
				return ret, fmt.Errorf("commitment H[%d] value assignment: %w", i, err)
			}
		}
		r.Bsb22Commitments = make([]kzg.Commitment[sw_bw6761.G1Affine], len(tProof.Bsb22Commitments))
		for i := range r.Bsb22Commitments {
			r.Bsb22Commitments[i], err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tProof.Bsb22Commitments[i])
			if err != nil {
				return ret, fmt.Errorf("bsb22 commitment %d value assignment: %w", i, err)
			}
		}
		// TODO: actually we compute the opening point later. Maybe we can precompute it here and later assert its correctness?
		r.BatchedProof, err = kzg.ValueOfBatchOpeningProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine](tProof.BatchedProof)
		if err != nil {
			return ret, fmt.Errorf("batch opening proof value assignment: %w", err)
		}
		r.ZShiftedOpening, err = kzg.ValueOfOpeningProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine](tProof.ZShiftedOpening)
		if err != nil {
			return ret, fmt.Errorf("z shifted opening proof value assignment: %w", err)
		}
	case *Proof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]:
		tProof, ok := proof.(*plonkbackend_bn254.Proof)
		if !ok {
			return ret, fmt.Errorf("expected sw_bls12377.Proof, got %T", proof)
		}
		for i := range r.LRO {
			r.LRO[i], err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tProof.LRO[i])
			if err != nil {
				return ret, fmt.Errorf("commitment LRO[%d] value assignment: %w", i, err)
			}
		}
		r.Z, err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tProof.Z)
		if err != nil {
			return ret, fmt.Errorf("commitment Z value assignment: %w", err)
		}
		for i := range r.H {
			r.H[i], err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tProof.H[i])
			if err != nil {
				return ret, fmt.Errorf("commitment H[%d] value assignment: %w", i, err)
			}
		}
		r.Bsb22Commitments = make([]kzg.Commitment[sw_bn254.G1Affine], len(tProof.Bsb22Commitments))
		for i := range r.Bsb22Commitments {
			r.Bsb22Commitments[i], err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tProof.Bsb22Commitments[i])
			if err != nil {
				return ret, fmt.Errorf("bsb22 commitment %d value assignment: %w", i, err)
			}
		}
		// TODO: actually we compute the opening point later. Maybe we can precompute it here and later assert its correctness?
		r.BatchedProof, err = kzg.ValueOfBatchOpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine](tProof.BatchedProof)
		if err != nil {
			return ret, fmt.Errorf("batch opening proof value assignment: %w", err)
		}
		r.ZShiftedOpening, err = kzg.ValueOfOpeningProof[sw_bn254.ScalarField, sw_bn254.G1Affine](tProof.ZShiftedOpening)
		if err != nil {
			return ret, fmt.Errorf("z shifted opening proof value assignment: %w", err)
		}
		// TODO: missing bls24317
	default:
		return ret, fmt.Errorf("unknown parametric type combination: %T", ret)
	}
	return ret, nil
}

// PlaceholderProof returns a placeholder proof witness to be use for compiling
// the outer circuit for witness alignment. For actual witness assignment use
// [ValueOfProof].
func PlaceholderProof[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](ccs constraint.ConstraintSystem) Proof[FR, G1El, G2El] {
	nbCommitments := len(ccs.GetCommitments().CommitmentIndexes())
	ret := Proof[FR, G1El, G2El]{
		BatchedProof: kzg.BatchOpeningProof[FR, G1El]{
			ClaimedValues: make([]emulated.Element[FR], 6+nbCommitments),
		},
		Bsb22Commitments: make([]kzg.Commitment[G1El], nbCommitments),
	}
	return ret
}

// BaseVerifyingKey is the common part of the verification key for the circuits
// with same size, same number of public inputs and same number of commitments.
// Use [PlaceholderBaseVerifyingKey] for creating a placeholder for compiling
// and [ValueOfBaseVerifyingKey] for witness assignment.
type BaseVerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {
	NbPublicVariables uint64

	// Commitment scheme that is used for an instantiation of PLONK
	Kzg kzg.VerifyingKey[G1El, G2El]

	// cosetShift generator of the coset on the small domain
	CosetShift emulated.Element[FR]
}

// CircuitVerifyingKey is the unique part of the verification key for the
// circuits with same [BaseVerifyingKey]. Use [PlaceholderCircuitVerifyingKey]
// for creating a placeholder for compiling the circuit or
// [ValueOfCircuitVerifyingKey] for witness assignment.
type CircuitVerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT] struct {
	// Size circuit
	Size      frontend.Variable
	SizeInv   emulated.Element[FR]
	Generator emulated.Element[FR]
	// S commitments to S1, S2, S3
	S [3]kzg.Commitment[G1El]

	// Commitments to ql, qr, qm, qo, qcp prepended with as many zeroes (ones for l) as there are public inputs.
	// In particular Qk is not complete.
	Ql, Qr, Qm, Qo, Qk kzg.Commitment[G1El]

	Qcp []kzg.Commitment[G1El]

	CommitmentConstraintIndexes []frontend.Variable
}

// VerifyingKey is a typed PLONK verification key. Use [ValueOfVerifyingKey] or
// [PlaceholderVerifyingKey] for initializing.
type VerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT] struct {
	BaseVerifyingKey[FR, G1El, G2El]
	CircuitVerifyingKey[FR, G1El]
}

// ValueOfBaseVerifyingKey assigns the base verification key from the witness.
// Use one of the verification keys for the same-sized circuits.
func ValueOfBaseVerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](vk backend_plonk.VerifyingKey) (BaseVerifyingKey[FR, G1El, G2El], error) {
	var ret BaseVerifyingKey[FR, G1El, G2El]
	var err error
	switch r := any(&ret).(type) {
	case *BaseVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]:
		tVk, ok := vk.(*plonkbackend_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12377.VerifyingKey, got %T", vk)
		}
		r.NbPublicVariables = tVk.NbPublicVariables
		r.Kzg, err = kzg.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine](tVk.Kzg)
		if err != nil {
			return ret, fmt.Errorf("verifying key witness assignment: %w", err)
		}
		r.CosetShift = sw_bls12377.NewScalar(tVk.CosetShift)
	case *BaseVerifyingKey[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine]:
		tVk, ok := vk.(*plonkbackend_bls12381.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12381.VerifyingKey, got %T", vk)
		}
		r.NbPublicVariables = tVk.NbPublicVariables
		r.Kzg, err = kzg.ValueOfVerifyingKeyFixed[sw_bls12381.G1Affine, sw_bls12381.G2Affine](tVk.Kzg)
		if err != nil {
			return ret, fmt.Errorf("verifying key witness assignment: %w", err)
		}
		r.CosetShift = sw_bls12381.NewScalar(tVk.CosetShift)
	case *BaseVerifyingKey[sw_bls24315.ScalarField, sw_bls24315.G1Affine, sw_bls24315.G2Affine]:
		tVk, ok := vk.(*plonkbackend_bls24315.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls24315.VerifyingKey, got %T", vk)
		}
		r.NbPublicVariables = tVk.NbPublicVariables
		r.Kzg, err = kzg.ValueOfVerifyingKeyFixed[sw_bls24315.G1Affine, sw_bls24315.G2Affine](tVk.Kzg)
		if err != nil {
			return ret, fmt.Errorf("verifying key witness assignment: %w", err)
		}
		r.CosetShift = sw_bls24315.NewScalar(tVk.CosetShift)
	case *BaseVerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine]:
		tVk, ok := vk.(*plonkbackend_bw6761.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12377.VerifyingKey, got %T", vk)
		}
		r.NbPublicVariables = tVk.NbPublicVariables
		r.Kzg, err = kzg.ValueOfVerifyingKeyFixed[sw_bw6761.G1Affine, sw_bw6761.G2Affine](tVk.Kzg)
		if err != nil {
			return ret, fmt.Errorf("verifying key witness assignment: %w", err)
		}
		r.CosetShift = sw_bw6761.NewScalar(tVk.CosetShift)
	case *BaseVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]:
		tVk, ok := vk.(*plonkbackend_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bn254.VerifyingKey, got %T", vk)
		}
		r.NbPublicVariables = tVk.NbPublicVariables
		r.Kzg, err = kzg.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine](tVk.Kzg)
		if err != nil {
			return ret, fmt.Errorf("verifying key witness assignment: %w", err)
		}
		r.CosetShift = sw_bn254.NewScalar(tVk.CosetShift)
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

// ValueOfCircuitVerifyingKey returns the witness for the unique part of the
// verification key. Returns an error if there is a mismatch between type
// arguments and given witness.
func ValueOfCircuitVerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT](vk backend_plonk.VerifyingKey) (CircuitVerifyingKey[FR, G1El], error) {
	var ret CircuitVerifyingKey[FR, G1El]
	var err error
	switch r := any(&ret).(type) {
	case *CircuitVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine]:
		tVk, ok := vk.(*plonkbackend_bls12377.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12377.VerifyingKey, got %T", vk)
		}
		r.Size = tVk.Size
		r.SizeInv = sw_bls12377.NewScalar(tVk.SizeInv)
		r.Generator = sw_bls12377.NewScalar(tVk.Generator)
		for i := range r.S {
			r.S[i], err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.S[i])
			if err != nil {
				return ret, fmt.Errorf("commitment S[%d] witness assignment: %w", i, err)
			}
		}
		r.Ql, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Ql)
		if err != nil {
			return ret, fmt.Errorf("commitment Ql witness assignment: %w", err)
		}
		r.Qr, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Qr)
		if err != nil {
			return ret, fmt.Errorf("commitment Qr witness assignment: %w", err)
		}
		r.Qm, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Qm)
		if err != nil {
			return ret, fmt.Errorf("commitment Qm witness assignment: %w", err)
		}
		r.Qo, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Qo)
		if err != nil {
			return ret, fmt.Errorf("commitment Qo witness assignment: %w", err)
		}
		r.Qk, err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Qk)
		if err != nil {
			return ret, fmt.Errorf("commitment Qk witness assignment: %w", err)
		}
		r.Qcp = make([]kzg.Commitment[sw_bls12377.G1Affine], len(tVk.Qcp))
		for i := range r.Qcp {
			r.Qcp[i], err = kzg.ValueOfCommitment[sw_bls12377.G1Affine](tVk.Qcp[i])
			if err != nil {
				return ret, fmt.Errorf("commitment Qcp[%d] witness assignment: %w", i, err)
			}
		}
		r.CommitmentConstraintIndexes = make([]frontend.Variable, len(tVk.CommitmentConstraintIndexes))
		for i := range r.CommitmentConstraintIndexes {
			r.CommitmentConstraintIndexes[i] = tVk.CommitmentConstraintIndexes[i]
		}
	case *CircuitVerifyingKey[sw_bls12381.ScalarField, sw_bls12381.G1Affine]:
		tVk, ok := vk.(*plonkbackend_bls12381.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12381.VerifyingKey, got %T", vk)
		}
		r.Size = tVk.Size
		r.SizeInv = sw_bls12381.NewScalar(tVk.SizeInv)
		r.Generator = sw_bls12381.NewScalar(tVk.Generator)
		for i := range r.S {
			r.S[i], err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tVk.S[i])
			if err != nil {
				return ret, fmt.Errorf("commitment S[%d] witness assignment: %w", i, err)
			}
		}
		r.Ql, err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tVk.Ql)
		if err != nil {
			return ret, fmt.Errorf("commitment Ql witness assignment: %w", err)
		}
		r.Qr, err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tVk.Qr)
		if err != nil {
			return ret, fmt.Errorf("commitment Qr witness assignment: %w", err)
		}
		r.Qm, err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tVk.Qm)
		if err != nil {
			return ret, fmt.Errorf("commitment Qm witness assignment: %w", err)
		}
		r.Qo, err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tVk.Qo)
		if err != nil {
			return ret, fmt.Errorf("commitment Qo witness assignment: %w", err)
		}
		r.Qk, err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tVk.Qk)
		if err != nil {
			return ret, fmt.Errorf("commitment Qk witness assignment: %w", err)
		}
		r.Qcp = make([]kzg.Commitment[sw_bls12381.G1Affine], len(tVk.Qcp))
		for i := range r.Qcp {
			r.Qcp[i], err = kzg.ValueOfCommitment[sw_bls12381.G1Affine](tVk.Qcp[i])
			if err != nil {
				return ret, fmt.Errorf("commitment Qcp[%d] witness assignment: %w", i, err)
			}
		}
		r.CommitmentConstraintIndexes = make([]frontend.Variable, len(tVk.CommitmentConstraintIndexes))
		for i := range r.CommitmentConstraintIndexes {
			r.CommitmentConstraintIndexes[i] = tVk.CommitmentConstraintIndexes[i]
		}
	case *CircuitVerifyingKey[sw_bls24315.ScalarField, sw_bls24315.G1Affine]:
		tVk, ok := vk.(*plonkbackend_bls24315.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls24315.VerifyingKey, got %T", vk)
		}
		r.Size = tVk.Size
		r.SizeInv = sw_bls24315.NewScalar(tVk.SizeInv)
		r.Generator = sw_bls24315.NewScalar(tVk.Generator)
		for i := range r.S {
			r.S[i], err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tVk.S[i])
			if err != nil {
				return ret, fmt.Errorf("commitment S[%d] witness assignment: %w", i, err)
			}
		}
		r.Ql, err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tVk.Ql)
		if err != nil {
			return ret, fmt.Errorf("commitment Ql witness assignment: %w", err)
		}
		r.Qr, err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tVk.Qr)
		if err != nil {
			return ret, fmt.Errorf("commitment Qr witness assignment: %w", err)
		}
		r.Qm, err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tVk.Qm)
		if err != nil {
			return ret, fmt.Errorf("commitment Qm witness assignment: %w", err)
		}
		r.Qo, err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tVk.Qo)
		if err != nil {
			return ret, fmt.Errorf("commitment Qo witness assignment: %w", err)
		}
		r.Qk, err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tVk.Qk)
		if err != nil {
			return ret, fmt.Errorf("commitment Qk witness assignment: %w", err)
		}
		r.Qcp = make([]kzg.Commitment[sw_bls24315.G1Affine], len(tVk.Qcp))
		for i := range r.Qcp {
			r.Qcp[i], err = kzg.ValueOfCommitment[sw_bls24315.G1Affine](tVk.Qcp[i])
			if err != nil {
				return ret, fmt.Errorf("commitment Qcp[%d] witness assignment: %w", i, err)
			}
		}
		r.CommitmentConstraintIndexes = make([]frontend.Variable, len(tVk.CommitmentConstraintIndexes))
		for i := range r.CommitmentConstraintIndexes {
			r.CommitmentConstraintIndexes[i] = tVk.CommitmentConstraintIndexes[i]
		}
	case *CircuitVerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine]:
		tVk, ok := vk.(*plonkbackend_bw6761.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bls12377.VerifyingKey, got %T", vk)
		}
		r.Size = tVk.Size
		r.SizeInv = sw_bw6761.NewScalar(tVk.SizeInv)
		r.Generator = sw_bw6761.NewScalar(tVk.Generator)
		for i := range r.S {
			r.S[i], err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tVk.S[i])
			if err != nil {
				return ret, fmt.Errorf("commitment S[%d] witness assignment: %w", i, err)
			}
		}
		r.Ql, err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tVk.Ql)
		if err != nil {
			return ret, fmt.Errorf("commitment Ql witness assignment: %w", err)
		}
		r.Qr, err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tVk.Qr)
		if err != nil {
			return ret, fmt.Errorf("commitment Qr witness assignment: %w", err)
		}
		r.Qm, err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tVk.Qm)
		if err != nil {
			return ret, fmt.Errorf("commitment Qm witness assignment: %w", err)
		}
		r.Qo, err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tVk.Qo)
		if err != nil {
			return ret, fmt.Errorf("commitment Qo witness assignment: %w", err)
		}
		r.Qk, err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tVk.Qk)
		if err != nil {
			return ret, fmt.Errorf("commitment Qk witness assignment: %w", err)
		}
		r.Qcp = make([]kzg.Commitment[sw_bw6761.G1Affine], len(tVk.Qcp))
		for i := range r.Qcp {
			r.Qcp[i], err = kzg.ValueOfCommitment[sw_bw6761.G1Affine](tVk.Qcp[i])
			if err != nil {
				return ret, fmt.Errorf("commitment Qcp[%d] witness assignment: %w", i, err)
			}
		}
		r.CommitmentConstraintIndexes = make([]frontend.Variable, len(tVk.CommitmentConstraintIndexes))
		for i := range r.CommitmentConstraintIndexes {
			r.CommitmentConstraintIndexes[i] = tVk.CommitmentConstraintIndexes[i]
		}
	case *CircuitVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine]:
		tVk, ok := vk.(*plonkbackend_bn254.VerifyingKey)
		if !ok {
			return ret, fmt.Errorf("expected bn254.VerifyingKey, got %T", vk)
		}
		r.Size = tVk.Size
		r.SizeInv = sw_bn254.NewScalar(tVk.SizeInv)
		r.Generator = sw_bn254.NewScalar(tVk.Generator)
		for i := range r.S {
			r.S[i], err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tVk.S[i])
			if err != nil {
				return ret, fmt.Errorf("commitment S[%d] witness assignment: %w", i, err)
			}
		}
		r.Ql, err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tVk.Ql)
		if err != nil {
			return ret, fmt.Errorf("commitment Ql witness assignment: %w", err)
		}
		r.Qr, err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tVk.Qr)
		if err != nil {
			return ret, fmt.Errorf("commitment Qr witness assignment: %w", err)
		}
		r.Qm, err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tVk.Qm)
		if err != nil {
			return ret, fmt.Errorf("commitment Qm witness assignment: %w", err)
		}
		r.Qo, err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tVk.Qo)
		if err != nil {
			return ret, fmt.Errorf("commitment Qo witness assignment: %w", err)
		}
		r.Qk, err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tVk.Qk)
		if err != nil {
			return ret, fmt.Errorf("commitment Qk witness assignment: %w", err)
		}
		r.Qcp = make([]kzg.Commitment[sw_bn254.G1Affine], len(tVk.Qcp))
		for i := range r.Qcp {
			r.Qcp[i], err = kzg.ValueOfCommitment[sw_bn254.G1Affine](tVk.Qcp[i])
			if err != nil {
				return ret, fmt.Errorf("commitment Qcp[%d] witness assignment: %w", i, err)
			}
		}
		r.CommitmentConstraintIndexes = make([]frontend.Variable, len(tVk.CommitmentConstraintIndexes))
		for i := range r.CommitmentConstraintIndexes {
			r.CommitmentConstraintIndexes[i] = tVk.CommitmentConstraintIndexes[i]
		}
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

// ValueOfVerifyingKey initializes witness from the given PLONK verifying key.
// It returns an error if there is a mismatch between the type parameters and
// the provided native verifying key.
func ValueOfVerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](vk backend_plonk.VerifyingKey) (VerifyingKey[FR, G1El, G2El], error) {
	var ret VerifyingKey[FR, G1El, G2El]
	bvk, err := ValueOfBaseVerifyingKey[FR, G1El, G2El](vk)
	if err != nil {
		return ret, fmt.Errorf("value of base verifying key: %w", err)
	}
	cvk, err := ValueOfCircuitVerifyingKey[FR, G1El](vk)
	if err != nil {
		return ret, fmt.Errorf("value of circuit verifying key: %w", err)
	}
	return VerifyingKey[FR, G1El, G2El]{
		BaseVerifyingKey:    bvk,
		CircuitVerifyingKey: cvk,
	}, nil
}

// PlaceholderBaseVerifyingKey returns placeholder of the base verification key
// common to circuits with same size, same number of public inputs and same
// number of commitments.
func PlaceholderBaseVerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](ccs constraint.ConstraintSystem) BaseVerifyingKey[FR, G1El, G2El] {
	nbPublic := ccs.GetNbPublicVariables()
	return BaseVerifyingKey[FR, G1El, G2El]{
		NbPublicVariables: uint64(nbPublic),
		Kzg:               kzg.PlaceholderVerifyingKey[G1El, G2El](),
	}
}

// PlaceholderCircuitVerifyingKey returns the placeholder for the unique part of
// the verification key with same [BaseVerifyingKey].
func PlaceholderCircuitVerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT](ccs constraint.ConstraintSystem) CircuitVerifyingKey[FR, G1El] {
	commitmentIndexes := ccs.GetCommitments().CommitmentIndexes()
	return CircuitVerifyingKey[FR, G1El]{
		CommitmentConstraintIndexes: make([]frontend.Variable, len(commitmentIndexes)),
		Qcp:                         make([]kzg.Commitment[G1El], len(commitmentIndexes)),
	}
}

// PlaceholderVerifyingKey returns placeholder of the verification key for
// compiling the outer circuit.
func PlaceholderVerifyingKey[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](ccs constraint.ConstraintSystem) VerifyingKey[FR, G1El, G2El] {
	return VerifyingKey[FR, G1El, G2El]{
		BaseVerifyingKey:    PlaceholderBaseVerifyingKey[FR, G1El, G2El](ccs),
		CircuitVerifyingKey: PlaceholderCircuitVerifyingKey[FR, G1El](ccs),
	}
}

// Witness is a public witness to verify the SNARK proof against. For assigning
// witness use [ValueOfWitness] and to create stub witness for compiling use
// [PlaceholderWitness].
type Witness[FR emulated.FieldParams] struct {
	Public []emulated.Element[FR]
}

// ValueOfWitness assigns a outer-circuit witness from the inner circuit
// witness. If there is a field mismatch then this method represents the witness
// inputs using field emulation. It returns an error if there is a mismatch
// between the type parameters and provided witness.
func ValueOfWitness[FR emulated.FieldParams](w witness.Witness) (Witness[FR], error) {
	var ret Witness[FR]
	pubw, err := w.Public()
	if err != nil {
		return ret, fmt.Errorf("get public witness: %w", err)
	}
	vec := pubw.Vector()
	switch s := any(&ret).(type) {
	case *Witness[sw_bls12377.ScalarField]:
		vect, ok := vec.(fr_bls12377.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bls12377.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bls12377.NewScalar(vect[i]))
		}
	case *Witness[sw_bls12381.ScalarField]:
		vect, ok := vec.(fr_bls12381.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bls12381.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bls12381.NewScalar(vect[i]))
		}
	case *Witness[sw_bls24315.ScalarField]:
		vect, ok := vec.(fr_bls24315.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bls24315.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bls24315.NewScalar(vect[i]))
		}
	case *Witness[sw_bw6761.ScalarField]:
		vect, ok := vec.(fr_bw6761.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bw6761.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bw6761.NewScalar(vect[i]))
		}
	case *Witness[sw_bn254.ScalarField]:
		vect, ok := vec.(fr_bn254.Vector)
		if !ok {
			return ret, fmt.Errorf("expected fr_bn254.Vector, got %T", vec)
		}
		for i := range vect {
			s.Public = append(s.Public, sw_bn254.NewScalar(vect[i]))
		}
	default:
		return ret, fmt.Errorf("unknown parametric type combination")
	}
	return ret, nil
}

// PlaceholderWitness creates a stub witness which can be used to allocate the
// variables in the circuit if the actual witness is not yet known. It takes
// into account the number of public inputs and number of used commitments.
func PlaceholderWitness[FR emulated.FieldParams](ccs constraint.ConstraintSystem) Witness[FR] {
	return Witness[FR]{
		Public: make([]emulated.Element[FR], ccs.GetNbPublicVariables()),
	}
}

// Verifier verifies PLONK proofs.
type Verifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	api       frontend.API
	scalarApi *emulated.Field[FR]
	curve     algebra.Curve[FR, G1El]
	pairing   algebra.Pairing[G1El, G2El, GtEl]
	kzg       *kzg.Verifier[FR, G1El, G2El, GtEl]
}

// NewVerifier returns a new [Verifier] instance.
func NewVerifier[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT](api frontend.API) (*Verifier[FR, G1El, G2El, GtEl], error) {
	curve, err := algebra.GetCurve[FR, G1El](api)
	if err != nil {
		return nil, fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return nil, fmt.Errorf("new pairing: %w", err)
	}
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new scalars: %w", err)
	}
	kzg, err := kzg.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return nil, fmt.Errorf("new kzg verifier: %w", err)
	}
	return &Verifier[FR, G1El, G2El, GtEl]{
		api:       api,
		scalarApi: f,
		curve:     curve,
		pairing:   pairing,
		kzg:       kzg,
	}, nil
}

// PrepareVerification returns a list of (openingProof, commitment, point), which are to be
// verified using kzg's BatchVerifyMultiPoints.
func (v *Verifier[FR, G1El, G2El, GtEl]) PrepareVerification(vk VerifyingKey[FR, G1El, G2El], proof Proof[FR, G1El, G2El], witness Witness[FR], opts ...VerifierOption) ([]kzg.Commitment[G1El], []kzg.OpeningProof[FR, G1El], []emulated.Element[FR], error) {

	var fr FR
	// helper: frontend.Variable -> emulated.Element[FR]
	toEmu := func(x frontend.Variable) *emulated.Element[FR] {
		bbits := bits.ToBinary(v.api, x, bits.WithNbDigits(fr.Modulus().BitLen()))
		return v.scalarApi.FromBits(bbits...)
	}
	cfg, err := newCfg(opts...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("apply options: %w", err)
	}
	if len(proof.Bsb22Commitments) != len(vk.Qcp) {
		return nil, nil, nil, fmt.Errorf("BSB22 commitment number mismatch")
	}

	var gamma, beta, alpha, zeta *emulated.Element[FR]

	if cfg.fsIn != nil {
		// -------- Poseidon2-FS branch（match zk/vk.go）--------
		h, err := hasher.NewPoseidon2FromParameters(v.api)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("poseidon2 params: %w", err)
		}

		if len(cfg.fsIn.Publics) != len(witness.Public) {
			return nil, nil, nil, fmt.Errorf("fs publics length %d != witness publics length %d", len(cfg.fsIn.Publics), len(witness.Public))
		}

		// helper: emulated.Element -> frontend.Variable
		toVar := func(e *emulated.Element[FR]) frontend.Variable {
			bs := v.scalarApi.ToBits(e)
			return v.api.FromBinary(bs...)
		}

		for i := range witness.Public {
			packed := toVar(&witness.Public[i])
			v.api.AssertIsEqual(packed, cfg.fsIn.Publics[i])
		}

		hashG1 := func(g G1Decomp) frontend.Variable {
			return h.HashG1Vars(hasher.G1DecomposedVars{XQ: g.XQ, XM: g.XM, YQ: g.YQ, YM: g.YM})
		}

		// gamma = CID_GAMMA, S1,S2,S3, Ql, Qr, Qm, Qo, Qk, QC, CW1, CW2, CW3, publics...
		var gIns []frontend.Variable
		gIns = append(gIns, cfg.fsIn.CIDGamma)
		gIns = append(gIns, hashG1(cfg.fsIn.S[0]), hashG1(cfg.fsIn.S[1]), hashG1(cfg.fsIn.S[2]))
		gIns = append(gIns, hashG1(cfg.fsIn.Ql), hashG1(cfg.fsIn.Qr), hashG1(cfg.fsIn.Qm), hashG1(cfg.fsIn.Qo), hashG1(cfg.fsIn.Qk))
		if len(cfg.fsIn.Qc) == 1 {
			gIns = append(gIns, hashG1(cfg.fsIn.Qc[0]))
		}

		gIns = append(gIns, hashG1(cfg.fsIn.W[0]), hashG1(cfg.fsIn.W[1]), hashG1(cfg.fsIn.W[2]))
		gIns = append(gIns, cfg.fsIn.Publics...)
		gammaVar := h.HashSumVars(gIns...)
		// gamma = v.scalarApi.NewElement(gammaVar)
		gamma = toEmu(gammaVar)

		// beta = CID_BETA, gamma
		betaVar := h.HashSumVars(cfg.fsIn.CIDBeta, gammaVar)
		// beta = v.scalarApi.NewElement(betaVar)
		beta = toEmu(betaVar)

		// alpha = CID_ALPHA, beta, BSB..., Z
		var aIns []frontend.Variable
		aIns = append(aIns, cfg.fsIn.CIDAlpha, betaVar)
		for i := range cfg.fsIn.BSB {
			aIns = append(aIns, hashG1(cfg.fsIn.BSB[i]))
		}
		aIns = append(aIns, hashG1(cfg.fsIn.Z))
		alphaVar := h.HashSumVars(aIns...)
		// alpha = v.scalarApi.NewElement(alphaVar)
		alpha = toEmu(alphaVar)

		// zeta = CID_ZETA, alpha, H0,H1,H2
		zetaVar := h.HashSumVars(cfg.fsIn.CIDZeta, alphaVar, hashG1(cfg.fsIn.H[0]), hashG1(cfg.fsIn.H[1]), hashG1(cfg.fsIn.H[2]))
		zeta = toEmu(zetaVar)

	} else {
		// -------- original branch（gnark transcript）--------
		fs, err := recursion.NewTranscript(v.api, fr.Modulus(), []string{"gamma", "beta", "alpha", "zeta"})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("init new transcript: %w", err)
		}
		if err := v.bindPublicData(fs, "gamma", vk, witness); err != nil {
			return nil, nil, nil, fmt.Errorf("bind public data: %w", err)
		}

		// The first challenge is derived using the public data: the commitments to the permutation,
		// the coefficients of the circuit, and the public inputs.
		// derive gamma from the Comm(blinded cl), Comm(blinded cr), Comm(blinded co)
		gamma, err = v.deriveRandomness(fs, "gamma", proof.LRO[0].G1El, proof.LRO[1].G1El, proof.LRO[2].G1El)
		if err != nil {
			return nil, nil, nil, err
		}

		// derive beta from Comm(l), Comm(r), Comm(o)
		beta, err = v.deriveRandomness(fs, "beta")
		if err != nil {
			return nil, nil, nil, err
		}

		// derive alpha from Comm(l), Comm(r), Comm(o), Com(Z), Bsb22Commitments
		// alpha from BSB..., Z
		alphaDeps := make([]G1El, len(proof.Bsb22Commitments)+1)
		for i := range proof.Bsb22Commitments {
			alphaDeps[i] = proof.Bsb22Commitments[i].G1El
		}
		alphaDeps[len(alphaDeps)-1] = proof.Z.G1El
		alpha, err = v.deriveRandomness(fs, "alpha", alphaDeps...)
		if err != nil {
			return nil, nil, nil, err
		}
		// derive zeta, the point of evaluation
		zeta, err = v.deriveRandomness(fs, "zeta", proof.H[0].G1El, proof.H[1].G1El, proof.H[2].G1El)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// evaluation of zhZetaZ=ζⁿ-1
	one := v.scalarApi.One()
	zetaPowerN := v.fixedExpN(vk.Size, zeta)   // ζⁿ
	zhZeta := v.scalarApi.Sub(zetaPowerN, one) // ζⁿ-1

	// L1 = (1/n)(ζⁿ-1)/(ζ-1)
	denom := v.scalarApi.Sub(zeta, one)
	lagrangeOne := v.scalarApi.Div(zhZeta, denom)
	lagrangeOne = v.scalarApi.Mul(lagrangeOne, &vk.SizeInv)
	lagrange := lagrangeOne

	// compute PI = ∑_{i<n} Lᵢ*wᵢ
	wPowI := one
	xiLi := v.scalarApi.Mul(lagrange, &witness.Public[0])
	pi := xiLi
	if len(witness.Public) != 1 {
		lagrange = v.scalarApi.Mul(lagrange, &vk.Generator)
		lagrange = v.scalarApi.Mul(lagrange, denom)
		wPowI = &vk.Generator
		denom = v.scalarApi.Sub(zeta, wPowI)
		lagrange = v.scalarApi.Div(lagrange, denom)
	}
	for i := 1; i < len(witness.Public); i++ {
		xiLi := v.scalarApi.Mul(lagrange, &witness.Public[i])
		pi = v.scalarApi.Add(pi, xiLi)
		if i+1 != len(witness.Public) {
			lagrange = v.scalarApi.Mul(lagrange, &vk.Generator)
			lagrange = v.scalarApi.Mul(lagrange, denom)
			wPowI = v.scalarApi.Mul(wPowI, &vk.Generator)
			denom = v.scalarApi.Sub(zeta, wPowI)
			lagrange = v.scalarApi.Div(lagrange, denom)
		}
	}

	if len(vk.CommitmentConstraintIndexes) > 0 {
		h, err := hasher.NewPoseidon2FromParameters(v.api)
		if err != nil {
			return nil, nil, nil, err
		}
		// prefixBSB := v.scalarApi.NewElement(hasher.PrefixBSB())
		prefixBSB := hasher.PrefixBSB()
		for i := range vk.CommitmentConstraintIndexes {
			// L_{m+CI}(ζ)
			li := v.computeIthLagrangeAtZeta(
				v.api.Add(vk.CommitmentConstraintIndexes[i], vk.NbPublicVariables),
				zeta, zetaPowerN, vk,
			)

			// HashG1(commitment)
			gVars := hasher.G1DecomposedVars{
				XQ: cfg.fsIn.BSB[i].XQ,
				XM: cfg.fsIn.BSB[i].XM,
				YQ: cfg.fsIn.BSB[i].YQ,
				YM: cfg.fsIn.BSB[i].YM,
			}
			hg1 := h.HashG1Vars(gVars)

			// HashCompress(PREFIX_BSB, hg1)
			hashedCmtVar := h.HashCompressVars(prefixBSB, hg1)

			// emHashed := v.scalarApi.NewElement(hashedCmtVar)
			emHashed := toEmu(hashedCmtVar)
			pi = v.scalarApi.Add(pi, v.scalarApi.Mul(emHashed, li))
		}
	}

	l := proof.BatchedProof.ClaimedValues[1]
	r := proof.BatchedProof.ClaimedValues[2]
	o := proof.BatchedProof.ClaimedValues[3]
	s1 := proof.BatchedProof.ClaimedValues[4]
	s2 := proof.BatchedProof.ClaimedValues[5]

	// Z(ωζ)
	zu := proof.ZShiftedOpening.ClaimedValue

	// α²*L₁(ζ)
	alphaSquareLagrangeOne := v.scalarApi.Mul(alpha, lagrangeOne)
	alphaSquareLagrangeOne = v.scalarApi.Mul(alphaSquareLagrangeOne, alpha)

	// computing the constant coefficient of the full algebraic relation
	// , corresponding to the value of the linearisation polynomiat at ζ
	// PI(ζ) - α²*L₁(ζ) + α(l(ζ)+β*s1(ζ)+γ)(r(ζ)+β*s2(ζ)+γ)(o(ζ)+γ)*z(ωζ)

	// _s1 = (l(ζ)+β*s1(ζ)+γ)
	lPlusBetaS1PlusGamma := v.scalarApi.Mul(&s1, beta)
	lPlusBetaS1PlusGamma = v.scalarApi.Add(lPlusBetaS1PlusGamma, &l)
	lPlusBetaS1PlusGamma = v.scalarApi.Add(lPlusBetaS1PlusGamma, gamma)

	// _s2 = (r(ζ)+β*s2(ζ)+γ)
	rPlusBetaS2PlusGamma := v.scalarApi.Mul(&s2, beta)
	rPlusBetaS2PlusGamma = v.scalarApi.Add(rPlusBetaS2PlusGamma, &r)
	rPlusBetaS2PlusGamma = v.scalarApi.Add(rPlusBetaS2PlusGamma, gamma)

	// _o = (o(ζ)+γ)
	_o := v.scalarApi.Add(&o, gamma)

	// _s1 = α*(Z(μζ))*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*(o(ζ)+γ)
	lPlusBetaS1PlusGammaTimesRPlusBetaS2PlusGamma := v.scalarApi.Mul(lPlusBetaS1PlusGamma, rPlusBetaS2PlusGamma)
	_s1 := v.scalarApi.Mul(lPlusBetaS1PlusGammaTimesRPlusBetaS2PlusGamma, _o)
	_s1 = v.scalarApi.Mul(_s1, alpha)
	_s1 = v.scalarApi.Mul(_s1, &zu)

	constLin := v.scalarApi.Add(pi, _s1)
	constLin = v.scalarApi.Sub(alphaSquareLagrangeOne, constLin)

	// check that the opening of the linearised polynomial is equal to -constLin
	openingLinPol := proof.BatchedProof.ClaimedValues[0]
	v.scalarApi.AssertIsEqual(&openingLinPol, constLin)

	// computing the linearised polynomial digest
	// α²*L₁(ζ)*[Z] +
	// _s1*[s3]+_s2*[Z] + l(ζ)*[Ql] +
	// l(ζ)r(ζ)*[Qm] + r(ζ)*[Qr] + o(ζ)*[Qo] + [Qk] + ∑ᵢQcp_(ζ)[Pi_i] -
	// Z_{H}(ζ)*(([H₀] + ζᵐ⁺²*[H₁] + ζ²⁽ᵐ⁺²⁾*[H₂])
	// where
	// _s1 =  α*(l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(ζ)+γ)*β*Z(μζ)
	// _s2 = -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)

	_s1 = v.scalarApi.Mul(lPlusBetaS1PlusGammaTimesRPlusBetaS2PlusGamma, beta) // (l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(ζ)+γ)*β
	_s1 = v.scalarApi.Mul(_s1, &zu)                                            // (l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(ζ)+γ)*β*Z(μζ)
	_s1 = v.scalarApi.Mul(_s1, alpha)                                          // α*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*β*Z(μζ)

	betaZeta := v.scalarApi.Mul(beta, zeta)                                  // β*ζ
	_s2 := v.scalarApi.Add(&l, betaZeta)                                     // l(ζ)+β*ζ
	_s2 = v.scalarApi.Add(_s2, gamma)                                        // (l(ζ)+β*ζ+γ)
	betaZetaCosetShift := v.scalarApi.Mul(betaZeta, &vk.CosetShift)          // u*β*ζ
	tmp := v.scalarApi.Add(&r, betaZetaCosetShift)                           // r(ζ)+β*u*ζ
	tmp = v.scalarApi.Add(tmp, gamma)                                        // r(ζ)+β*u*ζ+γ
	_s2 = v.scalarApi.Mul(_s2, tmp)                                          // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)
	betaZetaCosetShift = v.scalarApi.Mul(betaZetaCosetShift, &vk.CosetShift) // β*u²*ζ
	tmp = v.scalarApi.Add(betaZetaCosetShift, gamma)                         // β*u²*ζ+γ
	tmp = v.scalarApi.Add(tmp, &o)                                           // β*u²*ζ+γ+o
	_s2 = v.scalarApi.Mul(_s2, tmp)                                          // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)(o+β*u²*ζ+γ)
	_s2 = v.scalarApi.Mul(_s2, alpha)                                        // α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)(o+β*u²*ζ+γ)

	// α²*L₁(ζ) - α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	coeffZ := v.scalarApi.Sub(alphaSquareLagrangeOne, _s2)

	// l(ζ)*r(ζ)
	rl := v.scalarApi.Mul(&l, &r)

	// -ζⁿ⁺², -ζ²⁽ⁿ⁺²⁾, -(ζⁿ-1)
	zhZeta = v.scalarApi.Neg(zhZeta) // -(ζⁿ-1)
	zetaPowerNPlusTwo := v.scalarApi.Mul(zeta, zetaPowerN)
	zetaPowerNPlusTwo = v.scalarApi.Mul(zeta, zetaPowerNPlusTwo)                     // ζⁿ⁺²
	zetaPowerNPlusTwoSquare := v.scalarApi.Mul(zetaPowerNPlusTwo, zetaPowerNPlusTwo) // ζ²⁽ⁿ⁺²⁾

	// [H₀] + ζⁿ⁺²*[H₁] + ζ²⁽ⁿ⁺²⁾*[H₂]
	foldedH, err := v.curve.MultiScalarMul([]*G1El{&proof.H[1].G1El, &proof.H[2].G1El}, []*emulated.Element[FR]{zetaPowerNPlusTwo, zetaPowerNPlusTwoSquare})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("folded H: %w", err)
	}
	foldedH = v.curve.Add(foldedH, &proof.H[0].G1El)

	points := make([]*G1El, len(proof.Bsb22Commitments))
	for i := range proof.Bsb22Commitments {
		points[i] = &proof.Bsb22Commitments[i].G1El
	}
	points = append(points,
		&vk.Ql.G1El, &vk.Qr.G1El, &vk.Qm.G1El, &vk.Qo.G1El, // first part
		&vk.S[2].G1El, &proof.Z.G1El, // second part
		foldedH, // third part
	)

	qC := make([]*emulated.Element[FR], len(proof.Bsb22Commitments))
	for i := range proof.BatchedProof.ClaimedValues[6:] {
		qC[i] = &proof.BatchedProof.ClaimedValues[6+i]
	}
	scalars := append(qC,
		&l, &r, rl, &o, // first part
		_s1, coeffZ, // second part
		zhZeta, // third part
	)

	var msmOpts []algopts.AlgebraOption
	if cfg.withCompleteArithmetic {
		msmOpts = append(msmOpts, algopts.WithCompleteArithmetic())
	}
	linearizedPolynomialDigest, err := v.curve.MultiScalarMul(points, scalars, msmOpts...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("linearized polynomial digest MSM: %w", err)
	}
	if cfg.withCompleteArithmetic {
		// in PLONK Wo Commit ==> use AddUnified
		linearizedPolynomialDigest = v.curve.AddUnified(linearizedPolynomialDigest, &vk.Qk.G1El)
	} else {
		linearizedPolynomialDigest = v.curve.Add(linearizedPolynomialDigest, &vk.Qk.G1El)
	}

	// Fold the first proof
	foldedProof, foldedDigest, _, err := v.FoldProofExecStyle(
		cfg.fsIn.CIDGamma, // CID_GAMMA
		linearizedPolynomialDigest,
		proof,
		vk,
		zeta,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fold proof exec style: %w", err)
	}

	shiftedZeta := v.scalarApi.Mul(zeta, &vk.Generator)

	resCommitments := []kzg.Commitment[G1El]{foldedDigest, proof.Z}
	resProofs := []kzg.OpeningProof[FR, G1El]{foldedProof, proof.ZShiftedOpening}
	resPoints := []emulated.Element[FR]{*zeta, *shiftedZeta}

	return resCommitments, resProofs, resPoints, nil
}

// FoldProofExecStyle builds γ exactly like the execution code does and folds
// the digests/evaluations with powers of γ.
// It returns the folded opening proof and folded commitment (and γ for debugging/use).
// Requirements:
//   - len(vk.Qcp) >= 1 (we use exactly one QC to match the execution snippet)
//   - proof.BatchedProof.ClaimedValues has at least 7 elements:
//     [COL, CVL, CVR, CVO, CS1, CS2, CQC]
func (v *Verifier[FR, G1El, G2El, GtEl]) FoldProofExecStyle(
	cidGamma frontend.Variable, // CID_GAMMA（constant type)
	linearizedPolynomialDigest *G1El, // lpd
	proof Proof[FR, G1El, G2El], // CW1,CW2,CW3,Z(ωζ)
	vk VerifyingKey[FR, G1El, G2El], // S1,S2, QC
	zeta *emulated.Element[FR], // ζ
) (kzg.OpeningProof[FR, G1El], kzg.Commitment[G1El], *emulated.Element[FR], error) {

	var retP kzg.OpeningProof[FR, G1El]
	var retC kzg.Commitment[G1El]
	var fr FR
	toEmu := func(x frontend.Variable) *emulated.Element[FR] {
		bbits := bits.ToBinary(v.api, x, bits.WithNbDigits(fr.Modulus().BitLen()))
		return v.scalarApi.FromBits(bbits...)
	}

	// --- sanity checks to match the execution layout ---
	if len(vk.Qcp) < 1 {
		return retP, retC, nil, fmt.Errorf("need at least 1 QC commitment in vk.Qcp")
	}
	if len(proof.BatchedProof.ClaimedValues) < 7 {
		return retP, retC, nil, fmt.Errorf("claimed values need at least 7 entries [COL,CVL,CVR,CVO,CS1,CS2,CQC]")
	}

	// helper: emulated.Element[FR] -> frontend.Variable
	toVar := func(e *emulated.Element[FR]) frontend.Variable {
		bs := v.scalarApi.ToBits(e)
		return v.api.FromBinary(bs...)
	}

	// Poseidon2 hasher
	h, err := hasher.NewPoseidon2FromParameters(v.api)
	if err != nil {
		return retP, retC, nil, fmt.Errorf("poseidon2 params: %w", err)
	}

	// helper: hash G1 commitment via generic hint
	hashCommit := func(c kzg.Commitment[G1El]) (frontend.Variable, error) {
		return v.hashCommitmentByGenericHint(c)
	}

	// --------- 1) compute γ ---------
	// HashG1(lpd)
	hLpd, err := hashCommit(kzg.Commitment[G1El]{G1El: *linearizedPolynomialDigest})
	if err != nil {
		return retP, retC, nil, fmt.Errorf("hash lpd via hint: %w", err)
	}
	// HashG1(CW1..3)
	hCW1, err := hashCommit(proof.LRO[0])
	if err != nil {
		return retP, retC, nil, fmt.Errorf("hash CW1 via hint: %w", err)
	}
	hCW2, err := hashCommit(proof.LRO[1])
	if err != nil {
		return retP, retC, nil, fmt.Errorf("hash CW2 via hint: %w", err)
	}
	hCW3, err := hashCommit(proof.LRO[2])
	if err != nil {
		return retP, retC, nil, fmt.Errorf("hash CW3 via hint: %w", err)
	}
	// HashG1(S1,S2)
	hS1, err := hashCommit(vk.S[0])
	if err != nil {
		return retP, retC, nil, fmt.Errorf("hash S1 via hint: %w", err)
	}
	hS2, err := hashCommit(vk.S[1])
	if err != nil {
		return retP, retC, nil, fmt.Errorf("hash S2 via hint: %w", err)
	}
	// HashG1(QC) —— only use the first QC commitment, aligning with the execution code
	hQC, err := hashCommit(vk.Qcp[0])
	if err != nil {
		return retP, retC, nil, fmt.Errorf("hash QC via hint: %w", err)
	}

	// Claimed values, aligned with the execution code
	COL := toVar(&proof.BatchedProof.ClaimedValues[0])
	CVL := toVar(&proof.BatchedProof.ClaimedValues[1])
	CVR := toVar(&proof.BatchedProof.ClaimedValues[2])
	CVO := toVar(&proof.BatchedProof.ClaimedValues[3])
	CS1 := toVar(&proof.BatchedProof.ClaimedValues[4])
	CS2 := toVar(&proof.BatchedProof.ClaimedValues[5])
	CQC := toVar(&proof.BatchedProof.ClaimedValues[6])

	// CZO = Z(ω·ζ)
	CZO := toVar(&proof.ZShiftedOpening.ClaimedValue)

	// ζ
	zetaVar := toVar(zeta)

	// g := HashSum(CID_GAMMA, zeta, HashG1(lpd), HashG1(CW1..3), HashG1(S1), HashG1(S2), HashG1(QC),
	//              COL, CVL, CVR, CVO, CS1, CS2, CQC, CZO)
	gammaVar := h.HashSumVars(
		cidGamma,
		zetaVar,
		hLpd,
		hCW1, hCW2, hCW3,
		hS1, hS2, hQC,
		COL, CVL, CVR, CVO, CS1, CS2, CQC,
		CZO,
	)
	// gamma := v.scalarApi.NewElement(gammaVar)
	gamma := toEmu(gammaVar)

	// --------- 2) compute powers of g: [1, g, g², ..., g⁶] ---------
	const n7 = 7
	gs := make([]*emulated.Element[FR], n7)
	gs[0] = v.scalarApi.One()
	for i := 1; i < n7; i++ {
		gs[i] = v.scalarApi.Mul(gs[i-1], gamma)
	}

	// --------- 3) fold evaluations：foldeval = Σ v_i * gs[i] ---------
	// orders：COL, CVL, CVR, CVO, CS1, CS2, CQC (aligned with execution code)
	foldeval := v.scalarApi.Mul(&proof.BatchedProof.ClaimedValues[0], gs[0])
	for i := 1; i < n7; i++ {
		term := v.scalarApi.Mul(&proof.BatchedProof.ClaimedValues[i], gs[i])
		foldeval = v.scalarApi.Add(foldeval, term)
	}

	// --------- 4) fold digests：folddigest = Σ gs[i] * C_i ---------
	points := []*G1El{
		linearizedPolynomialDigest,
		&proof.LRO[0].G1El,
		&proof.LRO[1].G1El,
		&proof.LRO[2].G1El,
		&vk.S[0].G1El,
		&vk.S[1].G1El,
		&vk.Qcp[0].G1El,
	}
	foldedDigest, err := v.curve.MultiScalarMul(points, gs)
	if err != nil {
		return retP, retC, nil, fmt.Errorf("multi scalar mul (fold digests): %w", err)
	}

	// --------- 5) assemble return (align with kzg.FoldProof) ---------
	retP = kzg.OpeningProof[FR, G1El]{
		Quotient:     proof.BatchedProof.Quotient, // shared quotient with batched proof
		ClaimedValue: *foldeval,
	}
	retC = kzg.Commitment[G1El]{G1El: *foldedDigest}

	return retP, retC, gamma, nil
}

// AssertProof asserts that the SNARK proof holds for the given witness and
// verifying key.
func (v *Verifier[FR, G1El, G2El, GtEl]) AssertProof(vk VerifyingKey[FR, G1El, G2El], proof Proof[FR, G1El, G2El], witness Witness[FR], opts ...VerifierOption) error {

	commitments, proofs, points, err := v.PrepareVerification(vk, proof, witness, opts...)
	if err != nil {
		return err
	}

	err = v.kzg.BatchVerifyMultiPoints(commitments, proofs, points, vk.Kzg)
	if err != nil {
		return fmt.Errorf("batch verify kzg: %w", err)
	}
	return nil
}

// AssertSameProofs asserts that multiple proofs for the same circuit are valid.
func (v *Verifier[FR, G1El, G2El, GtEl]) AssertSameProofs(vk VerifyingKey[FR, G1El, G2El], proofs []Proof[FR, G1El, G2El], witnesses []Witness[FR], opts ...VerifierOption) error {
	if len(proofs) != len(witnesses) {
		return fmt.Errorf("proofs and witness length mismatch")
	}
	if len(proofs) == 0 {
		return fmt.Errorf("no proofs to check")
	}
	if len(proofs) == 1 {
		return v.AssertProof(vk, proofs[0], witnesses[0])
	}
	var foldedDigests []kzg.Commitment[G1El]
	var foldedProofs []kzg.OpeningProof[FR, G1El]
	var foldedPoints []emulated.Element[FR]
	for i := range proofs {
		dg, pr, pts, err := v.PrepareVerification(vk, proofs[i], witnesses[i], opts...)
		if err != nil {
			return fmt.Errorf("prepare proof %d: %w", i, err)
		}
		foldedDigests = append(foldedDigests, dg...)
		foldedProofs = append(foldedProofs, pr...)
		foldedPoints = append(foldedPoints, pts...)
	}
	if err := v.kzg.BatchVerifyMultiPoints(foldedDigests, foldedProofs, foldedPoints, vk.Kzg); err != nil {
		return fmt.Errorf("batch verify kzg: %w", err)
	}
	return nil
}

// AssertDifferentProofs asserts the validity of different proofs for different
// circuits. We define the base verification key bvk and per-circuit part in
// cvks. The selector which verification key to use ise given in slice switches.
// The proofs and witnesses are given in the arguments and must correspond to
// each other.
func (v *Verifier[FR, G1El, G2El, GtEl]) AssertDifferentProofs(bvk BaseVerifyingKey[FR, G1El, G2El], cvks []CircuitVerifyingKey[FR, G1El],
	switches []frontend.Variable, proofs []Proof[FR, G1El, G2El], witnesses []Witness[FR], opts ...VerifierOption) error {
	if len(proofs) != len(witnesses) || len(proofs) != len(switches) {
		return fmt.Errorf("input lengths mismatch")
	}
	if len(proofs) == 0 {
		return fmt.Errorf("no proofs to check")
	}
	var foldedDigests []kzg.Commitment[G1El]
	var foldedProofs []kzg.OpeningProof[FR, G1El]
	var foldedPoints []emulated.Element[FR]
	for i := range proofs {
		vk, err := v.SwitchVerificationKey(bvk, switches[i], cvks)
		if err != nil {
			return fmt.Errorf("switch verification key: %w", err)
		}
		dg, pr, pts, err := v.PrepareVerification(vk, proofs[i], witnesses[i], opts...)
		if err != nil {
			return fmt.Errorf("prepare proof %d: %w", i, err)
		}
		foldedDigests = append(foldedDigests, dg...)
		foldedProofs = append(foldedProofs, pr...)
		foldedPoints = append(foldedPoints, pts...)
	}
	if err := v.kzg.BatchVerifyMultiPoints(foldedDigests, foldedProofs, foldedPoints, bvk.Kzg); err != nil {
		return fmt.Errorf("batch verify kzg: %w", err)
	}
	return nil
}

func (v *Verifier[FR, G1El, G2El, GtEl]) bindPublicData(fs *fiatshamir.Transcript, challenge string, vk VerifyingKey[FR, G1El, G2El], witness Witness[FR]) error {

	// permutation
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.S[0].G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.S[1].G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.S[2].G1El)); err != nil {
		return err
	}

	// coefficients
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Ql.G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Qr.G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Qm.G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Qo.G1El)); err != nil {
		return err
	}
	if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Qk.G1El)); err != nil {
		return err
	}
	for i := range vk.Qcp {
		if err := fs.Bind(challenge, v.curve.MarshalG1(vk.Qcp[i].G1El)); err != nil {
			return err
		}
	}

	// public inputs
	for i := 0; i < len(witness.Public); i++ {
		if err := fs.Bind(challenge, v.curve.MarshalScalar(witness.Public[i])); err != nil {
			return err
		}
	}

	return nil
}

func (v *Verifier[FR, G1El, G2El, GtEl]) deriveRandomness(fs *fiatshamir.Transcript, challenge string, points ...G1El) (*emulated.Element[FR], error) {
	var fr FR
	for i := range points {
		if err := fs.Bind(challenge, v.curve.MarshalG1(points[i])); err != nil {
			return nil, fmt.Errorf("bind challenge %d: %w", i, err)
		}
	}
	b, err := fs.ComputeChallenge(challenge)
	if err != nil {
		return nil, fmt.Errorf("compute challenge: %w", err)
	}
	bbits := bits.ToBinary(v.api, b, bits.WithNbDigits(fr.Modulus().BitLen()))
	ret := v.scalarApi.FromBits(bbits...)
	return ret, nil
}

func (v *Verifier[FR, G1El, G2El, GtEl]) fixedExpN(n frontend.Variable, s *emulated.Element[FR]) *emulated.Element[FR] {
	// assume circuit of maximum size 2**30.
	const maxExpBits = 30
	// n is power of two.
	nBits := bits.ToBinary(v.api, n, bits.WithNbDigits(maxExpBits))
	res := v.scalarApi.Select(nBits[0], s, v.scalarApi.Zero())
	acc := v.scalarApi.Mul(s, s)
	for i := 1; i < maxExpBits-1; i++ {
		res = v.scalarApi.Select(nBits[i], acc, res)
		acc = v.scalarApi.Mul(acc, acc)
	}
	res = v.scalarApi.Select(nBits[maxExpBits-1], acc, res)
	return res
}

// computeIthLagrangeAtZeta computes L_{i}(\omega) = \omega^{i}/n (\zeta^{n}-1)/(\zeta-\omega^{i})
func (v *Verifier[FR, G1El, G2El, GtEl]) computeIthLagrangeAtZeta(exp frontend.Variable, zeta, zetaPowerN *emulated.Element[FR], vk VerifyingKey[FR, G1El, G2El]) *emulated.Element[FR] {
	// assume circuit of maximum size 2**30.
	const maxExpBits = 30

	one := v.scalarApi.One()
	num := v.scalarApi.Sub(zetaPowerN, one)

	// \omega^{i}
	iBits := bits.ToBinary(v.api, exp, bits.WithNbDigits(maxExpBits))

	omegai := v.scalarApi.Select(iBits[maxExpBits-1], &vk.Generator, one)
	for i := maxExpBits - 2; i >= 0; i-- {
		omegai = v.scalarApi.Mul(omegai, omegai)
		tmp := v.scalarApi.Mul(omegai, &vk.Generator)
		omegai = v.scalarApi.Select(iBits[i], tmp, omegai)
	}

	den := v.scalarApi.Sub(zeta, omegai)

	li := v.scalarApi.Div(num, den)
	li = v.scalarApi.Mul(li, &vk.SizeInv)
	li = v.scalarApi.Mul(li, omegai)

	return li
}

// SwitchVerificationKey returns a verification key by the index idx using the
// base verification key bvk and circuit specific verification key cvks[idx].
func (v *Verifier[FR, G1El, G2El, GtEl]) SwitchVerificationKey(bvk BaseVerifyingKey[FR, G1El, G2El], idx frontend.Variable, cvks []CircuitVerifyingKey[FR, G1El]) (VerifyingKey[FR, G1El, G2El], error) {
	var ret VerifyingKey[FR, G1El, G2El]
	if len(cvks) == 0 {
		return ret, fmt.Errorf("no circuit verification keys given")
	}
	if len(cvks) == 1 {
		// we don't need to switch. But the index needs to be 0.
		v.api.AssertIsEqual(idx, 0)
		return VerifyingKey[FR, G1El, G2El]{
			BaseVerifyingKey:    bvk,
			CircuitVerifyingKey: cvks[0],
		}, nil
	}
	nbIns := len(cvks)
	nbCmts := len(cvks[0].CommitmentConstraintIndexes)
	for i := range cvks {
		if len(cvks[i].CommitmentConstraintIndexes) != nbCmts {
			return ret, fmt.Errorf("mismatching number of commitments")
		}
		if len(cvks[i].Qcp) != nbCmts {
			return ret, fmt.Errorf("inconsistent circuit verification key")
		}
	}
	sizeEls := make([]frontend.Variable, nbIns)
	sizeInvEls := make([]*emulated.Element[FR], nbIns)
	genEls := make([]*emulated.Element[FR], nbIns)
	QlEls := make([]*G1El, nbIns)
	QrEls := make([]*G1El, nbIns)
	QmEls := make([]*G1El, nbIns)
	QoEls := make([]*G1El, nbIns)
	QkEls := make([]*G1El, nbIns)
	var SEls [3][]*G1El
	QcpEls := make([][]*G1El, nbCmts)
	cmtIndicesEls := make([][]frontend.Variable, nbCmts)
	for i := range SEls {
		SEls[i] = make([]*G1El, nbIns)
	}
	for i := range QcpEls {
		QcpEls[i] = make([]*G1El, nbIns)
		cmtIndicesEls[i] = make([]frontend.Variable, nbIns)
	}
	for i := range cvks {
		sizeEls[i] = cvks[i].Size
		sizeInvEls[i] = &cvks[i].SizeInv
		genEls[i] = &cvks[i].Generator
		QlEls[i] = &cvks[i].Ql.G1El
		QrEls[i] = &cvks[i].Qr.G1El
		QmEls[i] = &cvks[i].Qm.G1El
		QoEls[i] = &cvks[i].Qo.G1El
		QkEls[i] = &cvks[i].Qk.G1El
		for j := range SEls {
			SEls[j][i] = &cvks[i].S[j].G1El
		}
		for j := range QcpEls {
			QcpEls[j][i] = &cvks[i].Qcp[j].G1El
			cmtIndicesEls[j][i] = cvks[i].CommitmentConstraintIndexes[j]
		}
	}
	cvk := CircuitVerifyingKey[FR, G1El]{
		Size:      selector.Mux(v.api, idx, sizeEls...),
		SizeInv:   *v.scalarApi.Mux(idx, sizeInvEls...),
		Generator: *v.scalarApi.Mux(idx, genEls...),
		S: [3]kzg.Commitment[G1El]{
			{G1El: *v.curve.Mux(idx, SEls[0]...)},
			{G1El: *v.curve.Mux(idx, SEls[1]...)},
			{G1El: *v.curve.Mux(idx, SEls[2]...)},
		},
		Ql:                          kzg.Commitment[G1El]{G1El: *v.curve.Mux(idx, QlEls...)},
		Qr:                          kzg.Commitment[G1El]{G1El: *v.curve.Mux(idx, QrEls...)},
		Qm:                          kzg.Commitment[G1El]{G1El: *v.curve.Mux(idx, QmEls...)},
		Qo:                          kzg.Commitment[G1El]{G1El: *v.curve.Mux(idx, QoEls...)},
		Qk:                          kzg.Commitment[G1El]{G1El: *v.curve.Mux(idx, QkEls...)},
		Qcp:                         make([]kzg.Commitment[G1El], nbCmts),
		CommitmentConstraintIndexes: make([]frontend.Variable, nbCmts),
	}
	for i := range QcpEls {
		cvk.Qcp[i] = kzg.Commitment[G1El]{G1El: *v.curve.Mux(idx, QcpEls[i]...)}
		cvk.CommitmentConstraintIndexes[i] = selector.Mux(v.api, idx, cmtIndicesEls[i]...)
	}
	return VerifyingKey[FR, G1El, G2El]{
		BaseVerifyingKey:    bvk,
		CircuitVerifyingKey: cvk,
	}, nil
}
