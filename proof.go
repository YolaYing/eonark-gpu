package eonark

import (
	"errors"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonkbls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
)

type Proof struct {
	CW1, CW2, CW3, CH1, CH2, CH3, CPZ, BSB, HBP, HZO bls12381.G1Affine
	CZO, COL, CVL, CVR, CVO, CS1, CS2, CQC           fr.Element
}

func (me *Proof) ToGnarkPRoof() plonk.Proof {
	return &plonkbls12381.Proof{
		LRO:              [3]bls12381.G1Affine{me.CW1, me.CW2, me.CW3},
		Z:                me.CPZ,
		H:                [3]bls12381.G1Affine{me.CH1, me.CH2, me.CH3},
		Bsb22Commitments: []bls12381.G1Affine{me.BSB},
		BatchedProof: kzg.BatchOpeningProof{
			H:             me.HBP,
			ClaimedValues: []fr.Element{me.COL, me.CVL, me.CVR, me.CVO, me.CS1, me.CS2, me.CQC},
		},
		ZShiftedOpening: kzg.OpeningProof{
			H:            me.HZO,
			ClaimedValue: me.CZO,
		},
	}
}
func (me *Proof) FromGnarkProof(proof plonk.Proof) error {
	gp := proof.(*plonkbls12381.Proof)
	if len(gp.Bsb22Commitments) != 1 || len(gp.BatchedProof.ClaimedValues) != 7 {
		return errors.New("invalid number of commitments")
	}
	me.CW1 = gp.LRO[0]
	me.CW2 = gp.LRO[1]
	me.CW3 = gp.LRO[2]
	me.CH1 = gp.H[0]
	me.CH2 = gp.H[1]
	me.CH3 = gp.H[2]
	me.CPZ = gp.Z
	me.BSB = gp.Bsb22Commitments[0]
	me.HBP = gp.BatchedProof.H
	me.HZO = gp.ZShiftedOpening.H
	me.CZO = gp.ZShiftedOpening.ClaimedValue
	me.COL = gp.BatchedProof.ClaimedValues[0]
	me.CVL = gp.BatchedProof.ClaimedValues[1]
	me.CVR = gp.BatchedProof.ClaimedValues[2]
	me.CVO = gp.BatchedProof.ClaimedValues[3]
	me.CS1 = gp.BatchedProof.ClaimedValues[4]
	me.CS2 = gp.BatchedProof.ClaimedValues[5]
	me.CQC = gp.BatchedProof.ClaimedValues[6]
	return nil
}
func (me *Proof) WriteTo(w io.Writer) (int64, error) {
	enc := bls12381.NewEncoder(w)
	if err := enc.Encode(&me.CW1); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CW2); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CW3); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CH1); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CH2); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CH3); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CPZ); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.BSB); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.HBP); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.HZO); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CZO); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.COL); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CVL); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CVR); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CVO); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CS1); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CS2); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&me.CQC); err != nil {
		return enc.BytesWritten(), err
	}
	return enc.BytesWritten(), nil
}
func (me *Proof) ReadFrom(r io.Reader) (int64, error) {
	dec := bls12381.NewDecoder(r)
	if err := dec.Decode(&me.CW1); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CW2); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CW3); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CH1); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CH2); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CH3); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CPZ); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.BSB); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.HBP); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.HZO); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CZO); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.COL); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CVL); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CVR); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CVO); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CS1); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CS2); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&me.CQC); err != nil {
		return dec.BytesRead(), err
	}
	return dec.BytesRead(), nil
}
