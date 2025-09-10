package recursion

import (
	"fmt"
	"os"
	"testing"

	// curves and fields
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	frbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	// gnark
	plonkbls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"

	"github.com/eon-protocol/eonark/circuits/hasher"

	"github.com/eon-protocol/eonark"
)

//
// -------------------- Inner circuit layer --------------------
//

type innerCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
	Z frontend.Variable `gnark:",public"`
	W frontend.Variable `gnark:",public"`
}

func (me *innerCircuit) Define(api frontend.API) error {
	v := api.Mul(me.X, me.X)
	api.AssertIsEqual(v, 1)
	_, err := api.(frontend.Committer).Commit(me.X)
	if err != nil {
		return err
	}
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hasher.Write(me.X)
	sum := hasher.Sum()
	api.Println(sum)
	api.AssertIsEqual(sum, "35137972692771717943992759113612269767581262500164574105059686144346651628747")
	return nil
}

//
// -------------------- Outer circuit layer: Recursive verifier (BLS12-381), using Poseidon2-FS --------------------
//

type outerCircuitBLS struct {
	// Recursive verifier needs 3 components
	Proof        Proof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine]
	VerifyingKey VerifyingKey[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine] `gnark:"-"`

	// Inner public witness
	InnerWitness Witness[sw_bls12381.ScalarField]
	X            frontend.Variable `gnark:",public"`
	Y            frontend.Variable `gnark:",public"`
	Z            frontend.Variable `gnark:",public"`
	W            frontend.Variable `gnark:",public"`

	// Poseidon2-FS composed inputs, injected as options; not public
	FS FSInputs `gnark:"-"`
}

func (c *outerCircuitBLS) Define(api frontend.API) error {
	v, err := NewVerifier[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine, sw_bls12381.GTEl](api)
	if err != nil {
		return err
	}
	// Key point: pass FSInputs to force the use of Poseidon2-FS branch; CompleteArithmetic is safe
	return v.AssertProof(
		c.VerifyingKey,
		c.Proof,
		c.InnerWitness,
		WithCompleteArithmetic(),
		WithFSInputs(&c.FS),
	)
}

//
// -------------------- Tool: Decompose G1 point for FS --------------------
//

func decomposeG1ForFS(a bls12381.G1Affine) G1Decomp {
	d := hasher.DecomposeG1(a) // [2][2]fr.Element
	return G1Decomp{
		XQ: d[0][0].String(),
		XM: d[0][1].String(),
		YQ: d[1][0].String(),
		YM: d[1][1].String(),
	}
}

//
// -------------------- Test: BLS12-381 Inner/Outer Same Field + Poseidon2-FS --------------------
//

func Test_Recursion(t *testing.T) {
	assert := test.NewAssert(t)

	// 1) Compile the inner circuit: compile + prove (using SRS in share folder)
	var pk eonark.Pk
	err := pk.Compile(&innerCircuit{})
	assert.NoError(err)

	// inner circuit assignment: X=1 (satisfies X*X=1)
	innerAssign := &innerCircuit{X: 1, Y: 1, Z: 1, W: 1}

	// prove: return publics / proof
	publicsMine, _, proofMine, err := pk.Prove(innerAssign)
	assert.NoError(err)

	// sanity: run verification using verify functions in zk package
	vkMine := pk.Vk()
	assert.NoError(vkMine.Verify(proofMine, publicsMine))

	// 2) Bridge to gnark types: to align with the format required by the outer circuit
	gnarkVK := vkMine.ToGnarkVerifyingKey()
	gnarkProof := proofMine.ToGnarkPRoof()

	// 3) Extract public witness vector from gnark witness
	innerWitAll, err := frontend.NewWitness(innerAssign, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
	innerPubWit, err := innerWitAll.Public()
	assert.NoError(err)

	// type conversion: gnark types to sw_bls12381 types
	circuitVk, err := ValueOfVerifyingKey[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](gnarkVK)
	assert.NoError(err)
	circuitProof, err := ValueOfProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](gnarkProof)
	assert.NoError(err)
	circuitWitness, err := ValueOfWitness[sw_bls12381.ScalarField](innerPubWit)
	assert.NoError(err)

	// 4) Assemble Poseidon2-FS inputs (fsIn), strictly align with zk/vk.go feeding order
	//
	// First, extract gnark's "native bls12-381 struct" for G1 commitments
	vkBLS := gnarkVK.(*plonkbls12381.VerifyingKey)
	prBLS := gnarkProof.(*plonkbls12381.Proof)

	var fsIn FSInputs

	// (a) fixed scalars: γ, β, α, ζ
	// These are the constants used in the Poseidon2-FS circuit, hardcoded for the test
	// They are not public, but used in the FS transcript
	fsIn.CIDGamma = "12136437972164249638515815863518169381248623050802518443499856540155713785793"
	fsIn.CIDBeta = "18573803297957083279407999548582433273399322018814582391185078724486099338357"
	fsIn.CIDAlpha = "49747578351961873600101888628702675272467029400415710410441263855875020310598"
	fsIn.CIDZeta = "39057712567180736910604556313519348712189848041390074835666431785905701131882"

	// (b) VK：S, Ql..Qk, Qc
	fsIn.S[0] = decomposeG1ForFS(vkBLS.S[0])
	fsIn.S[1] = decomposeG1ForFS(vkBLS.S[1])
	fsIn.S[2] = decomposeG1ForFS(vkBLS.S[2])

	fsIn.Ql = decomposeG1ForFS(vkBLS.Ql)
	fsIn.Qr = decomposeG1ForFS(vkBLS.Qr)
	fsIn.Qm = decomposeG1ForFS(vkBLS.Qm)
	fsIn.Qo = decomposeG1ForFS(vkBLS.Qo)
	fsIn.Qk = decomposeG1ForFS(vkBLS.Qk)

	// only 1 QC commitment is used, aligning with the execution code
	fsIn.Qc = make([]G1Decomp, len(vkBLS.Qcp))
	for i := range vkBLS.Qcp {
		fsIn.Qc[i] = decomposeG1ForFS(vkBLS.Qcp[i])
	}

	// (c) Proof：W=LRO，BSB，Z，H
	fsIn.W[0] = decomposeG1ForFS(prBLS.LRO[0])
	fsIn.W[1] = decomposeG1ForFS(prBLS.LRO[1])
	fsIn.W[2] = decomposeG1ForFS(prBLS.LRO[2])

	fsIn.BSB = make([]G1Decomp, len(prBLS.Bsb22Commitments))
	for i := range prBLS.Bsb22Commitments {
		fsIn.BSB[i] = decomposeG1ForFS(prBLS.Bsb22Commitments[i])
	}

	fsIn.Z = decomposeG1ForFS(prBLS.Z)

	fsIn.H[0] = decomposeG1ForFS(prBLS.H[0])
	fsIn.H[1] = decomposeG1ForFS(prBLS.H[1])
	fsIn.H[2] = decomposeG1ForFS(prBLS.H[2])

	{
		v, ok := innerPubWit.Vector().(frbls12381.Vector)
		if !ok {
			t.Fatalf("unexpected public vector type: %T", innerPubWit.Vector())
		}
		fsIn.Publics = make([]frontend.Variable, len(v))
		for i := range v {
			// stringify each fr.Element to match the expected format
			// in the Poseidon2-FS circuit
			fsIn.Publics[i] = v[i].String()
		}
	}

	// 5) Outer circuit: placeholder + assignment
	outer := &outerCircuitBLS{
		Proof:        PlaceholderProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](pk.ToGnarkConstraintSystem()),
		InnerWitness: PlaceholderWitness[sw_bls12381.ScalarField](pk.ToGnarkConstraintSystem()),
		VerifyingKey: circuitVk, // non-public, injected via option
		FS:           fsIn,      // non-public, injected via option
	}
	assign := &outerCircuitBLS{
		Proof:        circuitProof,
		InnerWitness: circuitWitness,
		VerifyingKey: circuitVk,
		X:            0,
		Y:            0,
		Z:            0,
		W:            0,
		FS:           fsIn,
	}

	// just for debugging: test for circuit size segmentation
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, outer)
	if err != nil {
		t.Fatalf("compile outer: %v", err)
	}
	fmt.Printf("[outer] nbConstraints=%d nbPublic=%d nbSecret=%d\n",
		cs.GetNbConstraints(),
		cs.GetNbPublicVariables(),
		cs.GetNbSecretVariables(),
	)

	// 6) verify the outer circuit: IsSolved
	err = test.IsSolved(outer, assign, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
	fmt.Printf("outer circuit solved\n")

	// 7) verify circuit using zk package
	var pkOuter eonark.Pk
	if err := pkOuter.Compile(outer); err != nil {
		t.Fatalf("outer compile: %v", err)
	}

	vkOuter := pkOuter.Vk()

	publicsOuter, _, proofOuter, err := pkOuter.Prove(assign)
	if err != nil {
		t.Fatalf("outer prove: %v", err)
	}

	if err := vkOuter.Verify(proofOuter, publicsOuter); err != nil {
		t.Fatalf("outer vk.Verify: %v", err)
	}
	fmt.Printf("outer circuit verified\n")

	// ========= export outer circuit's proof / vk / KZG VK =========
	if err := os.MkdirAll("share", 0o755); err != nil {
		t.Fatalf("mkdir share: %v", err)
	}

	if file, err := os.Create("share/proof.outer.bin"); err == nil {
		if _, werr := proofOuter.WriteTo(file); werr != nil {
			t.Fatalf("write outer proof: %v", werr)
		}
		file.Close()
	} else {
		t.Fatalf("create proof.outer.bin: %v", err)
	}

	if file, err := os.Create("share/vk.outer.bin"); err == nil {
		if _, werr := vkOuter.WriteTo(file); werr != nil {
			t.Fatalf("write outer vk: %v", werr)
		}
		file.Close()
	} else {
		t.Fatalf("create vk.outer.bin: %v", err)
	}

	if file, err := os.Create("share/kzgvk.outer.bin"); err == nil {
		g1 := eonark.SRS_VK.G1
		g2 := eonark.SRS_VK.G2
		enc := bls12381.NewEncoder(file)
		if err := enc.Encode(&g1); err != nil {
			t.Fatalf("encode g1: %v", err)
		}
		if err := enc.Encode(&g2[0]); err != nil {
			t.Fatalf("encode g2[0]: %v", err)
		}
		if err := enc.Encode(&g2[1]); err != nil {
			t.Fatalf("encode g2[1]: %v", err)
		}
		file.Close()
	} else {
		t.Fatalf("create kzgvk.outer.bin: %v", err)
	}
	fmt.Printf("outer proof/vk/kzgvk exported\n")

}
