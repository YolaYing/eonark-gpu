package eonark

import (
	"encoding/hex"
	"log"

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
const SRS_DOWNLOAD_URL = "https://github.com/eon-protocol/eonark/releases/download/bin/SRS.PK.BIN"

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
var SRS_PK_HASH = func() (val [32]byte) {
	data, err := hex.DecodeString("8851342145732a79116fb72fc70f91b1f6360693174cd51b645944dab353e683")
	if err != nil {
		log.Fatalln(err)
	}
	copy(val[:], data)
	return
}()
var SRS_LK_HASH = func() (val [24][32]byte) {
	for i, v := range []string{
		"ce04c320a873fe535caec3f8082f57c33cff6ca2012fe84667d1424351f3d12e",
		"572cd55167233da429432edf01103ae633b17d1b7817597d45efb11f9ee17d72",
		"11c4bb73c072769ad60947e8137f958bcc6e5dd0b13327bebd2a9d9acecb72a1",
		"44022d1fd56aa9ee34effc7036b5142b3e14dba7db78ab5720a959d1c2e9cd0f",
		"f3e7bad8b8811c8828c911328ccf8a5721ed6656cb10da5dddb9f959788d4622",
		"97eec8b973855654a43dfc6086331652f5e032f03d30094f741dfca45c44cb8e",
		"31675f96198f08906630b83fd7798bd19543ec40930d559273feab5ae1b9413f",
		"b472723ce930c700bc8431329b213ae84705653e50138d328984bf63f3c708c7",
		"ebd3437825d174ea3e2479b9b133e79945bf1239c926137dda0affbafe5fa8dd",
		"3cc29b9578a5bff42cdbe2d53e5664f01bbfe9dc905264d1a4a1c69d57e72d65",
		"4edface1def21228d725628a13404a21da91954e09d8bea8d4dc26a1b6b33dbc",
		"58ecbc013c93b698b637f625f5fc1b7c2470623c716fa43bbd7d8766e405334c",
		"e5e862b82b4003124baaec31ce6854dea0f2f8fc209d921c4a837b8b4fdc4fb2",
		"94926b30804ccf229a4aed53e5e0adfc4fb38f74b221bd2600e791d39d665148",
		"14ebf2d83e74c53cc7247abb2c389e537afdb56dcd1116bfcef4ee04d5f53ea3",
		"63ccf7ccf79cf3b7a49a0de04fb9e094d926775324a1ff1039a45f91dd84af2c",
		"6a59062c73fa57c63b3e22231ffef57c768fa9b178c749020525a7a1fcb2225f",
		"e5b9044a981c24ff07a938bb0942766978dd28167b7e38246fdc108481d541a4",
		"c1447cfb226df90d929745f2f79b86766001b3b8d7ea53e5698494fe8aa98a8a",
		"4910250929b6cabbaa55c1b1dc50ad3b695acb1942e96eb4cd8abc74cdd3c1a6",
		"5c2d17655bb3b3823a7436dc9b8da2660455767f2cf9cac1cc20ed5d9d038eb5",
		"33b5fb5cff47d415238a9064d8e4fa395798519929db5c84dd20f7dfb88ae66a",
		"e5b9044a981c24ff07a938bb0942766978dd28167b7e38246fdc108481d541a4", // TODO
		"e5b9044a981c24ff07a938bb0942766978dd28167b7e38246fdc108481d541a4", // TODO
	} {
		data, err := hex.DecodeString(v)
		if err != nil {
			log.Fatalln(err)
		}
		copy(val[i][:], data)
	}
	return
}()
