package recursion

import (
	"fmt"
	"math/big"

	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"

	"github.com/eon-protocol/eonark/circuits/hasher"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/commitments/kzg"
)

// ---------- Gadget 1：transform Fp element to fixed-length little-endian bytes ----------
func fpElemToLittleEndianBytes(
	api frontend.API,
	fp *emulated.Field[sw_bls12381.BaseField],
	el *emulated.Element[sw_bls12381.BaseField],
	byteLen int, // bls12-381 base field ≈ 48 bytes
) []frontend.Variable {
	bitsLE := fp.ToBits(el) // LSB-first
	need := byteLen * 8     // 384
	if len(bitsLE) < need {
		zeros := make([]frontend.Variable, need-len(bitsLE))
		// pad with 0s
		for i := range zeros {
			zeros[i] = 0
		}
		bitsLE = append(bitsLE, zeros...)
	} else if len(bitsLE) > need {
		bitsLE = bitsLE[:need]
	}
	bytes := make([]frontend.Variable, byteLen)

	for i := 0; i < byteLen; i++ {
		v := frontend.Variable(0) // constant 0
		w := frontend.Variable(1)
		for k := 0; k < 8; k++ {
			v = api.Add(v, api.Mul(bitsLE[8*i+k], w))
			w = api.Add(w, w) // w *= 2
		}
		bytes[i] = v
	}
	return bytes
}

// ---------- Gadget 2：x < C's strict constraint circuit（LSB-first bits） ----------
func assertBitsLTConst(
	api frontend.API,
	xBitsLE []frontend.Variable,
	C *big.Int,
	nbits int,
) {
	one := frontend.Variable(1)
	two := frontend.Variable(2)

	// using D = C-1 as “x ≤ D”
	CM1 := new(big.Int).Sub(C, big.NewInt(1))

	// D's LSB-first bits
	dBits := make([]frontend.Variable, nbits)
	for i := 0; i < nbits; i++ {
		if CM1.Bit(i) == 1 {
			dBits[i] = 1
		} else {
			dBits[i] = 0
		}
	}

	prefixEq := frontend.Variable(1)
	for i := nbits - 1; i >= 0; i-- {
		xi, di := xBitsLE[i], dBits[i]
		// Assert: prefixEq * (1 - XOR(xi,di)) == 0
		api.AssertIsEqual(api.Mul(prefixEq, xi, api.Sub(1, di)), 0)
		// prefixEq *= (1 - XOR(xi,di))
		// XOR = xi + di - 2*xi*di
		xor := api.Sub(api.Add(xi, di), api.Mul(two, api.Mul(xi, di)))
		prefixEq = api.Mul(prefixEq, api.Sub(one, xor))
	}
}

// ---------- Core：for a single G1 commitment: hash G1 commitment(with the help Hint ) ----------
func (v *Verifier[FR, G1El, G2El, GtEl]) hashCommitmentByGenericHint(
	c kzg.Commitment[G1El],
) (frontend.Variable, error) {
	// Poseidon2 (电路侧)
	h, err := hasher.NewPoseidon2FromParameters(v.api)
	if err != nil {
		return nil, err
	}

	switch p := any(c.G1El).(type) {
	case sw_bls12381.G1Affine:
		// ---- 1) Fp（BLS12-381 base field）
		fp, err := emulated.NewField[sw_bls12381.BaseField](v.api)
		if err != nil {
			return nil, err
		}
		const baseFieldBytes = 48 // bls12-381 Fp ≈ 381 bits

		// ---- 2) fixed-length little-endian bytes
		xBytes := fpElemToLittleEndianBytes(v.api, fp, &p.X, baseFieldBytes)
		yBytes := fpElemToLittleEndianBytes(v.api, fp, &p.Y, baseFieldBytes)

		// ---- 3) prepare inputs for Hint
		Mbig := new(big.Int).Set(fr_bls12381.Modulus())
		Mbe := Mbig.Bytes()
		// remove leading zeros
		Mle := make([]byte, len(Mbe))
		for i := 0; i < len(Mbe); i++ {
			Mle[i] = Mbe[len(Mbe)-1-i]
		}
		ML := len(Mle)
		L := baseFieldBytes

		ins := make([]frontend.Variable, 0, 2+ML+2*baseFieldBytes)
		ins = append(ins, ML) // ML
		ins = append(ins, L)  // L
		for i := 0; i < ML; i++ {
			ins = append(ins, int(Mle[i])) // M[i] (little-endian)
		}
		ins = append(ins, xBytes...)
		ins = append(ins, yBytes...)

		// ---- 4) call Hint
		outs, err := v.api.Compiler().NewHint(hasher.HintDecomposeMod_LE, 4, ins...)
		if err != nil {
			return nil, fmt.Errorf("hint decompose (mod bytes): %w", err)
		}
		XQ, XM, YQ, YM := outs[0], outs[1], outs[2], outs[3]

		// ---- 5) constraints：X == XM + M*XQ，Y == YM + M*YQ
		// (a) range：XM,YM < M；(b) width：XQ,YQ ≤ ~126 bits
		rBits := Mbig.BitLen() // 255 for bls12-381/Fr
		xmBits := bits.ToBinary(v.api, XM, bits.WithNbDigits(rBits))
		ymBits := bits.ToBinary(v.api, YM, bits.WithNbDigits(rBits))
		const qBits = 126
		xqBits := bits.ToBinary(v.api, XQ, bits.WithNbDigits(qBits))
		yqBits := bits.ToBinary(v.api, YQ, bits.WithNbDigits(qBits))

		assertBitsLTConst(v.api, xmBits, Mbig, rBits)
		assertBitsLTConst(v.api, ymBits, Mbig, rBits)

		xmFP := fp.FromBits(xmBits...)
		ymFP := fp.FromBits(ymBits...)
		xqFP := fp.FromBits(xqBits...)
		yqFP := fp.FromBits(yqBits...)
		Mfp := fp.NewElement(Mbig)

		fp.AssertIsEqual(&p.X, fp.Add(xmFP, fp.Mul(Mfp, xqFP)))
		fp.AssertIsEqual(&p.Y, fp.Add(ymFP, fp.Mul(Mfp, yqFP)))

		// ---- 6) hash G1 point
		return h.HashG1Vars(hasher.G1DecomposedVars{
			XQ: XQ, XM: XM, YQ: YQ, YM: YM,
		}), nil

	default:
		return nil, fmt.Errorf("unsupported curve element %T (expected bls12-381)", p)
	}
}
