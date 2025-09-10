// native (off-circuit) Poseidon hasher functions
package hasher

import (
	"log"
	"math/big"

	"github.com/eon-protocol/eonark"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

// Compress runs the native Poseidon2 permutation on (x,y) and returns
// perm([x,y])[1] + y, matching the circuit's Compress semantics (t=2).
func Compress(x, y fr.Element) fr.Element {
	vars := [2]fr.Element{x, y}
	if err := GetPermutation().Permutation(vars[:]); err != nil {
		log.Fatalln(err)
	}
	var ret fr.Element
	ret.Add(&vars[1], &y)
	return ret
}

// Sum folds a sequence using Compress(acc, v) starting from zero.
func Sum(val ...fr.Element) fr.Element {
	var ret fr.Element
	for _, v := range val {
		ret = Compress(ret, v)
	}
	return ret
}

// Address hashes a verifying key into a single field element using the same
// composition as the circuit (see comments inline). This matches the
// circuit-side Hash* functions when the same parameters/seed are used.
func Address(val eonark.Vk) fr.Element {
	sz := fr.NewElement(uint64(val.SZ))
	ci := fr.NewElement(uint64(val.CI))
	sc := Compress(sz, ci)

	s1 := DigestHash(val.S1)
	s2 := DigestHash(val.S2)
	s3 := DigestHash(val.S3)
	ql := DigestHash(val.QL)
	qr := DigestHash(val.QR)
	qm := DigestHash(val.QM)
	qo := DigestHash(val.QO)
	qk := DigestHash(val.QK)
	qcp := DigestHash(val.QC)
	return Sum(sz, ci, sc, s1, s2, s3, ql, qr, qm, qo, qk, qcp)
}

// DigestHash commits a KZG digest (X,Y) by splitting X into quotient/remainder
// modulo Fr modulus and conditionally negating the remainder based on the
// lexicographic sign of Y.
func DigestHash(val kzg.Digest) fr.Element {
	var ez, em fr.Element
	var iz, im big.Int
	val.X.BigInt(&iz).DivMod(&iz, fr.Modulus(), &im)
	ez.SetBigInt(&iz)
	em.SetBigInt(&im)
	if val.Y.LexicographicallyLargest() {
		em.Neg(&em)
	}
	return Compress(ez, em)
}

// DecomposeG1 splits a G1Affine into (xq,xm,yq,ym) such that
// X = xq * r + xm, Y = yq * r + ym, where r is the scalar field modulus.
// The output order is [[xq,xm],[yq,ym]].
func DecomposeG1(val bls12381.G1Affine) [2][2]fr.Element {
	var ixq, ixm, iyq, iym big.Int
	var exq, exm, eyq, eym fr.Element
	val.X.BigInt(&ixq)
	val.Y.BigInt(&iyq)
	ixq.DivMod(&ixq, fr.Modulus(), &ixm)
	iyq.DivMod(&iyq, fr.Modulus(), &iym)
	exq.SetBigInt(&ixq)
	exm.SetBigInt(&ixm)
	eyq.SetBigInt(&iyq)
	eym.SetBigInt(&iym)
	return [2][2]fr.Element{{exq, exm}, {eyq, eym}}
}

// HashG1 ≡ Compress(Compress(xq,xm), Compress(yq,ym)).
func HashG1(val bls12381.G1Affine) fr.Element {
	decompose := DecomposeG1(val)
	x := HashCompress(decompose[0][0], decompose[0][1])
	y := HashCompress(decompose[1][0], decompose[1][1])
	return HashCompress(x, y)
}

func HashCompress(x, y fr.Element) fr.Element {
	vars := [2]fr.Element{x, y}
	if err := GetPermutation().Permutation(vars[:]); err != nil {
		log.Fatalln(err)
	}
	var ret fr.Element
	ret.Add(&vars[1], &y)
	return ret
}

func HashSum(val ...fr.Element) fr.Element {
	var ret fr.Element
	for _, v := range val {
		ret = HashCompress(ret, v)
	}
	return ret
}
