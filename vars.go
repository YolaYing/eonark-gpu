package eonark

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/std/recursion/plonk"
)

const NUM_PUBLIC = 4
const SRS_SIZE = (1 << 24) + 3
const HASH_T = 2
const HASH_RF = 8
const HASH_RP = 56

var FIELD = ecc.BLS12_381.ScalarField()
var OPT_PROVER = plonk.GetNativeProverOptions(FIELD, FIELD)
var OPT_VERIFIER = plonk.GetNativeVerifierOptions(FIELD, FIELD)
var COSET_SHIFT = fr.NewElement(7)
var CID_GAMMA = func() (val fr.Element) {
	val.SetString("12136437972164249638515815863518169381248623050802518443499856540155713785793")
	return
}()
var CID_BETA = func() (val fr.Element) {
	val.SetString("18573803297957083279407999548582433273399322018814582391185078724486099338357")
	return
}()
var CID_ALPHA = func() (val fr.Element) {
	val.SetString("49747578351961873600101888628702675272467029400415710410441263855875020310598")
	return
}()
var CID_ZETA = func() (val fr.Element) {
	val.SetString("39057712567180736910604556313519348712189848041390074835666431785905701131882")
	return
}()
var PREFIX_BSB = func() (val fr.Element) {
	val.SetString("25462560578134928990029001067183171577145376707459712415971543462128145703592")
	return
}()
var SRS_VK = func() (vk kzg.VerifyingKey) {
	vk.G1.X = fp.Element{0x5cb38790fd530c16, 0x7817fc679976fff5, 0x154f95c7143ba1c1, 0xf0ae6acdf3d0e747, 0xedce6ecc21dbf440, 0x120177419e0bfb75}
	vk.G1.Y = fp.Element{0xbaac93d50ce72271, 0x8c22631a7918fd8e, 0xdd595f13570725ce, 0x51ac582950405194, 0x0e1c8c3fad0059c0, 0x0bbc3efc5008a26a}
	vk.G2[0].X.A0 = fp.Element{0xf5f28fa202940a10, 0xb3f5fb2687b4961a, 0xa1a893b53e2ae580, 0x9894999d1a3caee9, 0x6f67b7631863366b, 0x058191924350bcd7}
	vk.G2[0].X.A1 = fp.Element{0xa5a9c0759e23f606, 0xaaa0c59dbccd60c3, 0x3bb17e18e2867806, 0x1b1ab6cc8541b367, 0xc2b6ed0ef2158547, 0x11922a097360edf3}
	vk.G2[0].Y.A0 = fp.Element{0x4c730af860494c4a, 0x597cfa1f5e369c5a, 0xe7e6856caa0a635a, 0xbbefb5e96e0d495f, 0x07d3a975f0ef25a2, 0x0083fd8e7e80dae5}
	vk.G2[0].Y.A1 = fp.Element{0xadc0fc92df64b05d, 0x18aa270a2b1461dc, 0x86adac6a3be4eba0, 0x79495c4ec93da33a, 0xe7175850a43ccaed, 0x0b2bc2a163de1bf2}
	vk.G2[1].X.A0 = fp.Element{0x15e1097c7828dc0a, 0x2aa06ace61c1b130, 0x8c43b205a5263211, 0xaf11b7649ede9ba6, 0xd56da49c60ce2091, 0x040722f4c800f47c}
	vk.G2[1].X.A1 = fp.Element{0x746bd07fb2b2f7a2, 0x49def89b08978eed, 0xd9509e2051d1fa5f, 0xe0e00f28da6797c8, 0x12d115103e83ee0c, 0x024d09ebd14b3e90}
	vk.G2[1].Y.A0 = fp.Element{0xbf8e801ab678aed2, 0xb3864e5dc3b4ab5d, 0x11adefd8b64ff089, 0x58fead521a719499, 0xe664cc2c7e075221, 0x1022f460c363ba3a}
	vk.G2[1].Y.A1 = fp.Element{0xef492939d07e69e9, 0x18ac555fd8bcb2e8, 0x0ae772a284821ecd, 0x8fad1e1abb04db50, 0x08ea78f01c631c6f, 0x0b079ca24f558ddc}
	vk.Lines[0] = bls12381.PrecomputeLines(vk.G2[0])
	vk.Lines[1] = bls12381.PrecomputeLines(vk.G2[1])
	return
}()
var SRS_PK_HASH = [32]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
}
var SRS_LK_HASH [][32]byte = [][32]byte{SRS_PK_HASH, SRS_PK_HASH}
