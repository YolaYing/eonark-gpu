// Package hasher provides a Poseidon2-based hashing gadget for gnark circuits.
// Currently only supports BLS12-381.

package hasher

import (
	"errors"
	"math/big"

	poseidonbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

var (
	ErrInvalidSizebuffer = errors.New("the size of the input should match the size of the hash buffer")
)

// In-circuit Poseidon2 permutation implementation.
type Permutation struct {
	api    frontend.API
	params parameters
}

// parameters holds the Poseidon2 parameters needed by the circuit.
type parameters struct {
	width           int
	degreeSBox      int
	nbFullRounds    int
	nbPartialRounds int
	// Round keys arranged as [round][lane].
	roundKeys [][]big.Int
}

// ---------------------- constructor (reads from hasher/vars.go) ----------------------

// NewPoseidon2FromParameters builds a Permutation from WIDTH/ROUND_* and SEED
// defined in vars.go.
func NewPoseidon2FromParameters(api frontend.API) (*Permutation, error) {
	width, rf, rp := WIDTH, ROUND_FULL, ROUND_PARTIAL
	useSeed := USESEED
	seed := SEED

	// degreeSBox is obtained from the bls12-381 Poseidon2 parameters.
	params := parameters{
		width:           width,
		degreeSBox:      poseidonbls12381.DegreeSBox(),
		nbFullRounds:    rf,
		nbPartialRounds: rp,
	}

	// Instantiate concrete params (including round keys) with/without seed.
	var concreteParams *poseidonbls12381.Parameters
	if useSeed {
		concreteParams = poseidonbls12381.NewParametersWithSeed(width, rf, rp, seed)
	} else {
		concreteParams = poseidonbls12381.NewParameters(width, rf, rp)
	}

	// Copy round keys into big.Int constants for circuit use.
	params.roundKeys = make([][]big.Int, len(concreteParams.RoundKeys))
	for i := range params.roundKeys {
		params.roundKeys[i] = make([]big.Int, len(concreteParams.RoundKeys[i]))
		for j := range params.roundKeys[i] {
			concreteParams.RoundKeys[i][j].BigInt(&params.roundKeys[i][j])
		}
	}

	return &Permutation{api: api, params: params}, nil
}

// ---------------------- permutation implementation ----------------------

func (h *Permutation) sBox(index int, input []frontend.Variable) {
	tmp := input[index]
	switch h.params.degreeSBox {
	case 3:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(tmp, input[index])
	case 5:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	case 7:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	case 17:
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], input[index])
		input[index] = h.api.Mul(input[index], tmp)
	case -1:
		// Inverse S-box (x -> x^{-1}) variant.
		input[index] = h.api.Inverse(input[index])
	default:
		panic("unsupported sBox degree")
	}
}

// matMulM4InPlace applies s <- M4*s using the addition chain given in Poseidon2 appendix B.
func (h *Permutation) matMulM4InPlace(s []frontend.Variable) {
	c := len(s) / 4
	for i := 0; i < c; i++ {
		t0 := h.api.Add(s[4*i], s[4*i+1])   // s0+s1
		t1 := h.api.Add(s[4*i+2], s[4*i+3]) // s2+s3
		t2 := h.api.Mul(s[4*i+1], 2)
		t2 = h.api.Add(t2, t1) // 2s1+t1
		t3 := h.api.Mul(s[4*i+3], 2)
		t3 = h.api.Add(t3, t0) // 2s3+t0
		t4 := h.api.Mul(t1, 4)
		t4 = h.api.Add(t4, t3) // 4t1+t3
		t5 := h.api.Mul(t0, 4)
		t5 = h.api.Add(t5, t2)  // 4t0+t2
		t6 := h.api.Add(t3, t5) // t3+t5
		t7 := h.api.Add(t2, t4) // t2+t4
		s[4*i] = t6
		s[4*i+1] = t5
		s[4*i+2] = t7
		s[4*i+3] = t4
	}
}

// matMulExternalInPlace applies the external MDS matrix for t in {2,3,4} or any multiple of 4.
func (h *Permutation) matMulExternalInPlace(input []frontend.Variable) {
	switch h.params.width {
	case 2:
		tmp := h.api.Add(input[0], input[1])
		input[0] = h.api.Add(tmp, input[0])
		input[1] = h.api.Add(tmp, input[1])
	case 3:
		tmp := h.api.Add(input[0], input[1])
		tmp = h.api.Add(tmp, input[2])
		input[0] = h.api.Add(input[0], tmp)
		input[1] = h.api.Add(input[1], tmp)
		input[2] = h.api.Add(input[2], tmp)
	case 4:
		h.matMulM4InPlace(input)
	default:
		// For width being a multiple of 4, MDS is circ(2*M4, M4, ..., M4).
		if h.params.width%4 != 0 {
			panic("width must be 2, 3, 4 or multiple of 4")
		}
		h.matMulM4InPlace(input)
		tmp := make([]frontend.Variable, 4)
		for i := 0; i < h.params.width/4; i++ {
			tmp[0] = h.api.Add(tmp[0], input[4*i])
			tmp[1] = h.api.Add(tmp[1], input[4*i+1])
			tmp[2] = h.api.Add(tmp[2], input[4*i+2])
			tmp[3] = h.api.Add(tmp[3], input[4*i+3])
		}
		for i := 0; i < h.params.width/4; i++ {
			input[4*i] = h.api.Add(input[4*i], tmp[0])
			input[4*i+1] = h.api.Add(input[4*i+1], tmp[1])
			input[4*i+2] = h.api.Add(input[4*i+2], tmp[2])
			input[4*i+3] = h.api.Add(input[4*i+3], tmp[3])
		}
	}
}

// matMulInternalInPlace applies the sparse internal MDS (only t in {2,3}, aligned with gnark-crypto).
func (h *Permutation) matMulInternalInPlace(input []frontend.Variable) {
	switch h.params.width {
	case 2:
		sum := h.api.Add(input[0], input[1])
		input[0] = h.api.Add(input[0], sum)
		input[1] = h.api.Mul(2, input[1])
		input[1] = h.api.Add(input[1], sum)
	case 3:
		sum := h.api.Add(input[0], input[1])
		sum = h.api.Add(sum, input[2])
		input[0] = h.api.Add(input[0], sum)
		input[1] = h.api.Add(input[1], sum)
		input[2] = h.api.Mul(input[2], 2)
		input[2] = h.api.Add(input[2], sum)
	default:
		panic("only T=2,3 is supported for internal matrix")
	}
}

func (h *Permutation) addRoundKeyInPlace(round int, input []frontend.Variable) {
	for i := 0; i < len(h.params.roundKeys[round]); i++ {
		input[i] = h.api.Add(input[i], h.params.roundKeys[round][i])
	}
}

// Permutation applies the Poseidon2 permutation in place.
func (h *Permutation) Permutation(input []frontend.Variable) error {
	if len(input) != h.params.width {
		return ErrInvalidSizebuffer
	}

	// Pre-external MDS.
	h.matMulExternalInPlace(input)

	rf := h.params.nbFullRounds / 2
	// First half of full rounds.
	for i := 0; i < rf; i++ {
		h.addRoundKeyInPlace(i, input)
		for j := 0; j < h.params.width; j++ {
			h.sBox(j, input)
		}
		h.matMulExternalInPlace(input)
	}
	// Partial rounds (S-box applied only to lane 0).
	for i := rf; i < rf+h.params.nbPartialRounds; i++ {
		h.addRoundKeyInPlace(i, input)
		h.sBox(0, input)
		h.matMulInternalInPlace(input)
	}
	// Second half of full rounds.
	for i := rf + h.params.nbPartialRounds; i < h.params.nbFullRounds+h.params.nbPartialRounds; i++ {
		h.addRoundKeyInPlace(i, input)
		for j := 0; j < h.params.width; j++ {
			h.sBox(j, input)
		}
		h.matMulExternalInPlace(input)
	}
	return nil
}

// Compress is the two-word sponge compression function for t=2.
// It returns perm([left,right])[1] + right (i.e., the right lane after permutation plus the original right).
func (h *Permutation) Compress(left, right frontend.Variable) frontend.Variable {
	if h.params.width != 2 {
		panic("poseidon2: Compress can only be used when t=2")
	}
	vars := [2]frontend.Variable{left, right}
	if err := h.Permutation(vars[:]); err != nil {
		panic(err)
	}
	return h.api.Add(vars[1], right)
}

// ---------------------- HashCompress/HashSum/HashG1 circuit ----------------------
// Circuit-level equivalents to native HashCompress/HashSum/HashG1.
// Note: no DivMod decomposition is performed inside the circuit;
// (xq, xm, yq, ym) are expected as witnesses for a decomposed G1Affine.

// G1DecomposedVars represents the decomposed form of a G1Affine:
// X = xq * r + xm,  Y = yq * r + ym,
// where (xq, xm, yq, ym) are circuit variables provided as witness.
type G1DecomposedVars struct {
	XQ frontend.Variable
	XM frontend.Variable
	YQ frontend.Variable
	YM frontend.Variable
}

// HashCompressVars is the in-circuit variant of the native HashCompress.
func (h *Permutation) HashCompressVars(x, y frontend.Variable) frontend.Variable {
	return h.Compress(x, y)
}

// HashSumVars folds values from zero using HashCompressVars.
func (h *Permutation) HashSumVars(vals ...frontend.Variable) frontend.Variable {
	var acc frontend.Variable = 0
	for i := range vals {
		acc = h.Compress(acc, vals[i])
	}
	return acc
}

// HashG1Vars matches the native HashG1: compress x=(xq,xm), then y=(yq,ym), then (x,y).
func (h *Permutation) HashG1Vars(g G1DecomposedVars) frontend.Variable {
	x := h.Compress(g.XQ, g.XM)
	y := h.Compress(g.YQ, g.YM)
	return h.Compress(x, y)
}
