// Centralizes Poseidon2 parameters for both native and circuit code.
package hasher

import (
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
)

const WIDTH = 2
const ROUND_FULL = 8
const ROUND_PARTIAL = 56
const USESEED = true
const SEED = "EON_POSEIDON2_HASH_SEED"

// GetPermutation returns a native Poseidon2 permutation using the parameters above.
var GetPermutation = sync.OnceValue(func() *poseidon2.Permutation {
	if USESEED {
		return poseidon2.NewPermutationWithSeed(WIDTH, ROUND_FULL, ROUND_PARTIAL, SEED)
	}
	return poseidon2.NewPermutation(WIDTH, ROUND_FULL, ROUND_PARTIAL)
})

var PREFIX_BSB = func() (val fr.Element) {
	val.SetString("25462560578134928990029001067183171577145376707459712415971543462128145703592")
	return
}()

func PrefixBSB() *big.Int {
	var b big.Int
	PREFIX_BSB.BigInt(&b)
	return &b
}
