package hasher

import (
	"fmt"
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	frbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// This test suite cross-checks the circuit implementation against the native
// Poseidon2 implementation (gnark-crypto) for permutation and hash helpers.

type poseidon2PermCircuit struct {
	Input  []frontend.Variable
	Output []frontend.Variable `gnark:",public"`
}

func (c *poseidon2PermCircuit) Define(api frontend.API) error {
	perm, err := NewPoseidon2FromParameters(api)

	if err != nil {
		return fmt.Errorf("new poseidon2 perm: %w", err)
	}
	if err := perm.Permutation(c.Input); err != nil {
		return fmt.Errorf("permute: %w", err)
	}
	for i := 0; i < len(c.Input); i++ {
		api.AssertIsEqual(c.Output[i], c.Input[i])
	}
	return nil
}

// Test: Poseidon2 permutation circuit vs native implementation

func TestPoseidon2Permutation_MatchesNative(t *testing.T) {
	assert := test.NewAssert(t)

	// Native Poseidon2 permutation
	nativePerm := GetPermutation()

	// 8 iterations
	for it := 0; it < 8; it++ {
		var in, out [WIDTH]frbls12381.Element
		for i := 0; i < WIDTH; i++ {
			in[i].SetRandom()
		}
		copy(out[:], in[:])

		// Native permutation
		if err := nativePerm.Permutation(out[:]); err != nil {
			t.Fatalf("native permutation failed: %v", err)
		}

		// Circuit permutation
		var circuit poseidon2PermCircuit
		var validWitness poseidon2PermCircuit

		circuit.Input = make([]frontend.Variable, WIDTH)
		circuit.Output = make([]frontend.Variable, WIDTH)

		validWitness.Input = make([]frontend.Variable, WIDTH)
		validWitness.Output = make([]frontend.Variable, WIDTH)

		for i := 0; i < WIDTH; i++ {
			validWitness.Input[i] = in[i].String()
			validWitness.Output[i] = out[i].String()
		}

		// Check circuit
		assert.CheckCircuit(
			&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithCurves(ecc.BLS12_381),
		)
		log.Println("pass one permutation test iteration")
	}
}
