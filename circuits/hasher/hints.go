// Package hasher provides a generic decomposition hint used by circuits
// that need to split values modulo the scalar field modulus.
package hasher

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
)

// leBytesToBigInt builds a big.Int from little-endian bytes (b[0] is the least significant byte).
func leBytesToBigInt(b []byte) *big.Int {
	var z big.Int
	for i := len(b) - 1; i >= 0; i-- {
		z.Lsh(&z, 8)
		z.Add(&z, big.NewInt(int64(b[i])))
	}
	return &z
}

// HintDecomposeMod_LE is a generic hint that performs quotient/remainder decomposition
// w.r.t. a modulus M, given X and Y as little-endian byte arrays.
//
// ins  = [ M, L, X_0, X_1, ..., X_(L-1), Y_0, ..., Y_(L-1) ]
// outs = [ XQ, XM, YQ, YM ]
func HintDecomposeMod_LE(_ *big.Int, ins, outs []*big.Int) error {
	if len(outs) != 4 {
		return fmt.Errorf("need 4 outs (XQ,XM,YQ,YM), got %d", len(outs))
	}
	if len(ins) < 2 {
		return fmt.Errorf("inputs must start with ML and L")
	}
	ML := ins[0].Int64()
	L := ins[1].Int64()
	if ML <= 0 || L <= 0 {
		return fmt.Errorf("invalid ML(%d) or L(%d)", ML, L)
	}
	expect := 2 + int(ML) + 2*int(L)
	if len(ins) != expect {
		return fmt.Errorf("inputs len mismatch: got %d, want %d", len(ins), expect)
	}

	mb := make([]byte, ML)
	for i := 0; i < int(ML); i++ {
		mb[i] = byte(ins[2+i].Uint64() & 0xff)
	}
	xb := make([]byte, L)
	yb := make([]byte, L)
	base := 2 + int(ML)
	for i := 0; i < int(L); i++ {
		xb[i] = byte(ins[base+i].Uint64() & 0xff)
		yb[i] = byte(ins[base+int(L)+i].Uint64() & 0xff)
	}
	M := leBytesToBigInt(mb)
	X := leBytesToBigInt(xb)
	Y := leBytesToBigInt(yb)

	var xq, xm, yq, ym big.Int
	xq.DivMod(X, M, &xm)
	yq.DivMod(Y, M, &ym)

	outs[0].Set(&xq)
	outs[1].Set(&xm)
	outs[2].Set(&yq)
	outs[3].Set(&ym)
	return nil
}

func init() {
	solver.RegisterHint(HintDecomposeMod_LE)
}
