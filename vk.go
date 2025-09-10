package eonark

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonkbls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
)

type Vk struct {
	S1, S2, S3, QL, QR, QM, QO, QK, QC bls12381.G1Affine
	CI                                 uint32
	SZ                                 uint8
}

func (me *Vk) ToGnarkVerifyingKey() plonk.VerifyingKey {
	size := fr.NewElement(1 << me.SZ)
	var sizeinv fr.Element
	sizeinv.Inverse(&size)
	generator, err := fr.Generator(1 << me.SZ)
	if err != nil {
		log.Fatalln(err)
	}
	return &plonkbls12381.VerifyingKey{
		Size:                        1 << me.SZ,
		SizeInv:                     sizeinv,
		Generator:                   generator,
		NbPublicVariables:           NUM_PUBLIC,
		Kzg:                         SRS_VK,
		CosetShift:                  fr.NewElement(7),
		S:                           [3]bls12381.G1Affine{me.S1, me.S2, me.S3},
		Ql:                          me.QL,
		Qr:                          me.QR,
		Qm:                          me.QM,
		Qo:                          me.QO,
		Qk:                          me.QK,
		Qcp:                         []bls12381.G1Affine{me.QC},
		CommitmentConstraintIndexes: []uint64{uint64(me.CI)},
	}
}

func (me *Vk) FromGnarkVerifyingKey(vk plonk.VerifyingKey) error {
	cvk := vk.(*plonkbls12381.VerifyingKey)
	if bits.OnesCount64(cvk.Size) != 1 {
		return errors.New("vk.size should be power of 2")
	}
	if cvk.NbPublicVariables != NUM_PUBLIC {
		return fmt.Errorf("NbPublicVariables = %d != %d", cvk.NbPublicVariables, NUM_PUBLIC)
	}
	if cvk.Kzg != SRS_VK {
		return errors.New("invalid KZG VK")
	}
	if cvk.CosetShift != COSET_SHIFT {
		return errors.New("invalid coset shift")
	}
	if len(cvk.Qcp) != 1 || len(cvk.CommitmentConstraintIndexes) != 1 {
		return errors.New("invalid number of commitments")
	}
	me.SZ = uint8(bits.TrailingZeros64(cvk.Size))      // TODO CHECK
	me.CI = uint32(cvk.CommitmentConstraintIndexes[0]) // TODO CHECK
	me.S1 = cvk.S[0]
	me.S2 = cvk.S[1]
	me.S3 = cvk.S[2]
	me.QL = cvk.Ql
	me.QR = cvk.Qr
	me.QM = cvk.Qm
	me.QO = cvk.Qo
	me.QK = cvk.Qk
	me.QC = cvk.Qcp[0]
	return nil
}

func (me *Vk) Verify(proof *Proof, publics [4]fr.Element) error {
	for _, v := range []bls12381.G1Affine{proof.CW1, proof.CW2, proof.CW3, proof.CPZ, proof.CH1, proof.CH2, proof.CH3, proof.BSB, proof.HBP, proof.HZO} {
		if !v.IsInSubGroup() {
			return errors.New("G1 not in sub group")
		}
	}
	gamma := HashSum(append([]fr.Element{CID_GAMMA, HashG1(me.S1), HashG1(me.S2), HashG1(me.S3), HashG1(me.QL), HashG1(me.QR), HashG1(me.QM), HashG1(me.QO), HashG1(me.QK), HashG1(me.QC), HashG1(proof.CW1), HashG1(proof.CW2), HashG1(proof.CW3)}, publics[:]...)...)
	beta := HashSum(CID_BETA, gamma)
	alpha := HashSum(CID_ALPHA, beta, HashG1(proof.BSB), HashG1(proof.CPZ))
	zeta := HashSum(CID_ZETA, alpha, HashG1(proof.CH1), HashG1(proof.CH2), HashG1(proof.CH3))
	one := fr.One()
	generator, err := fr.Generator(1 << me.SZ)
	if err != nil {
		return err
	}
	var pi, lin, tmp, s1, s2, cz, rl, zetana2zh, zetana2sqzh, zh, sizeinv, l0, alpha2l0, zetas, foldeval fr.Element
	zh.Exp(zeta, big.NewInt(int64(1<<me.SZ)))
	zh.Sub(&zh, &one)                                                 // ζⁿ-1
	sizeinv.SetUint64(1 << me.SZ).Inverse(&sizeinv)                   // 1/n
	l0.Sub(&zeta, &one).Inverse(&l0).Mul(&l0, &zh).Mul(&l0, &sizeinv) // 1/n * (ζ^n-1)/(ζ-1)
	alpha2l0.Mul(&l0, &alpha).Mul(&alpha2l0, &alpha)                  // α²/n * (ζ^n-1)/(ζ-1)
	hashedcmt := HashCompress(PREFIX_BSB, HashG1(proof.BSB))
	tmp.Exp(generator, big.NewInt(NUM_PUBLIC+int64(me.CI)))
	pi.Mul(&zh, &tmp).Div(&pi, tmp.Sub(&zeta, &tmp)).Mul(&pi, &sizeinv).Mul(&pi, &hashedcmt)
	ws := [4]fr.Element{one, one, one, one}
	for i := 1; i < len(ws); i++ {
		ws[i].Mul(&ws[i-1], &generator)
	}
	for i := 0; i < len(publics); i++ {
		pi.Add(&pi, tmp.Sub(&zeta, &ws[i]).Inverse(&tmp).Mul(&tmp, &zh).Mul(&tmp, &sizeinv).Mul(&tmp, &ws[i]).Mul(&tmp, &publics[i]))
	}
	lin.Mul(&beta, &proof.CS1).Add(&lin, &gamma).Add(&lin, &proof.CVL).Mul(&lin, tmp.Mul(&proof.CS2, &beta).Add(&tmp, &gamma).Add(&tmp, &proof.CVR)).Mul(&lin, tmp.Add(&proof.CVO, &gamma)).Mul(&lin, &alpha).Mul(&lin, &proof.CZO).Sub(&lin, &alpha2l0).Add(&lin, &pi).Neg(&lin) // -[PI(ζ) - α²*L₁(ζ) + α(l(ζ)+β*s1(ζ)+γ)(r(ζ)+β*s2(ζ)+γ)(o(ζ)+γ)*z(ωζ)]
	if !lin.Equal(&proof.COL) {
		return errors.New("algebraic relation does not hold")
	}
	s1.Mul(&beta, &proof.CS1).Add(&s1, &proof.CVL).Add(&s1, &gamma).Mul(&s1, tmp.Mul(&beta, &proof.CS2).Add(&tmp, &proof.CVR).Add(&tmp, &gamma)).Mul(&s1, &beta).Mul(&s1, &alpha).Mul(&s1, &proof.CZO)                                                                                                           // α*(l(ζ)+β*s1(β)+γ)*(r(ζ)+β*s2(β)+γ)*β*Z(μζ)
	s2.Mul(&beta, &zeta).Add(&s2, &gamma).Add(&s2, &proof.CVL).Mul(&s2, tmp.Mul(&beta, &COSET_SHIFT).Mul(&tmp, &zeta).Add(&tmp, &gamma).Add(&tmp, &proof.CVR)).Mul(&s2, tmp.Mul(&beta, &COSET_SHIFT).Mul(&tmp, &COSET_SHIFT).Mul(&tmp, &zeta).Add(&tmp, &proof.CVO).Add(&tmp, &gamma)).Mul(&s2, &alpha).Neg(&s2) // -α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	cz.Add(&alpha2l0, &s2)                                                                                                                                                                                                                                                                                       // α²*L₁(ζ) - α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
	rl.Mul(&proof.CVL, &proof.CVR)                                                                                                                                                                                                                                                                               // l(ζ)*r(ζ)

	zetana2zh.Exp(zeta, big.NewInt(int64(1<<me.SZ)+2))
	zetana2sqzh.Mul(&zetana2zh, &zetana2zh).Mul(&zetana2sqzh, &zh).Neg(&zetana2sqzh) // -ζ²⁽ⁿ⁺²⁾*(ζⁿ-1)
	zetana2zh.Mul(&zetana2zh, &zh).Neg(&zetana2zh)                                   // -ζⁿ⁺²*(ζⁿ-1)
	zh.Neg(&zh)
	zetas.Mul(&zeta, &generator)
	var lpd bls12381.G1Affine
	points := []bls12381.G1Affine{proof.BSB, me.QL, me.QR, me.QM, me.QO, me.QK, me.S3, proof.CPZ, proof.CH1, proof.CH2, proof.CH3}
	scalars := []fr.Element{proof.CQC, proof.CVL, proof.CVR, rl, proof.CVO, one, s1, cz, zh, zetana2zh, zetana2sqzh}
	if _, err := lpd.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
		return err
	}

	var folddigest bls12381.G1Affine
	g := HashSum(CID_GAMMA, zeta, HashG1(lpd), HashG1(proof.CW1), HashG1(proof.CW2), HashG1(proof.CW3), HashG1(me.S1), HashG1(me.S2), HashG1(me.QC), proof.COL, proof.CVL, proof.CVR, proof.CVO, proof.CS1, proof.CS2, proof.CQC, proof.CZO)
	gs := [7]fr.Element{one, one, one, one, one, one, one}
	for i := 1; i < len(gs); i++ {
		gs[i].Mul(&gs[i-1], &g)
	}
	for i, v := range []fr.Element{proof.COL, proof.CVL, proof.CVR, proof.CVO, proof.CS1, proof.CS2, proof.CQC} {
		foldeval.Add(&foldeval, tmp.Mul(&v, &gs[i]))
	}
	_, err = folddigest.MultiExp([]bls12381.G1Affine{lpd, proof.CW1, proof.CW2, proof.CW3, me.S1, me.S2, me.QC}, gs[:], ecc.MultiExpConfig{})
	if err != nil {
		return err
	}
	return kzg.BatchVerifyMultiPoints(
		[]bls12381.G1Affine{folddigest, proof.CPZ},
		[]kzg.OpeningProof{{H: proof.HBP, ClaimedValue: foldeval}, {H: proof.HZO, ClaimedValue: proof.CZO}},
		[]fr.Element{zeta, zetas},
		SRS_VK,
	)
}

func (me *Vk) Address() fr.Element {
	return HashCompress(HashSum(HashG1(me.S1), HashG1(me.S2), HashG1(me.S3), HashG1(me.QL), HashG1(me.QR), HashG1(me.QM), HashG1(me.QO), HashG1(me.QK), HashG1(me.QC)), HashCompress(fr.NewElement(uint64(me.CI)), fr.NewElement(uint64(me.SZ))))
}

func (me *Vk) WriteTo(w io.Writer) (int64, error) {
	enc := bls12381.NewEncoder(w)
	if err := enc.Encode(&me.S1); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.S2); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.S3); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.QL); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.QR); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.QM); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.QO); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.QK); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.QC); err != nil {
		return enc.BytesWritten(), err
	}
	buf := [4]byte{}
	binary.BigEndian.PutUint32(buf[:], me.CI)
	if n, err := w.Write(buf[:]); err != nil {
		return int64(n) + enc.BytesWritten(), err
	}
	if n, err := w.Write([]byte{me.SZ}); err != nil {
		return int64(n) + 4 + enc.BytesWritten(), err
	}
	return 5 + enc.BytesWritten(), nil
}

func (me *Vk) ReadFrom(r io.Reader) (int64, error) {
	dec := bls12381.NewDecoder(r)
	if err := dec.Decode(&me.S1); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.S2); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.S3); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.QL); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.QR); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.QM); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.QO); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.QK); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.QC); err != nil {
		return dec.BytesRead(), err
	}
	buf := [4]byte{}
	if n, err := io.ReadFull(r, buf[:]); err != nil {
		return int64(n) + dec.BytesRead(), err
	}
	me.CI = binary.BigEndian.Uint32(buf[:])
	sz := [1]byte{}
	if n, err := io.ReadFull(r, sz[:]); err != nil {
		return int64(n) + 4 + dec.BytesRead(), err
	}
	me.SZ = sz[0]
	return dec.BytesRead() + 5, nil
}
