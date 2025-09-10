# Recursion Circuit

A **PLONK verifier circuit** that checks proofs inside another circuit.

## Package overview
- **circuit.go** — defines the recursive PLONK verifier circuit (outer).
- **funcs.go** — helpers for converting gnark `VerifyingKey`, `Proof`, and witnesses into in-circuit representations (including FS transcript inputs).
- **opts.go** — prover/verifier options aligned with recursion on BLS12-381.
- **circuit_test.go** — end-to-end test: compiles an inner circuit, proves it natively, and verifies it inside the outer circuit.

## Usage

### 1） Produce a native proof for the inner circuit

```go
// Compile + Prove the inner circuit natively (example uses eonark helpers).
// Make sure native prover/verifier opts are compatible with in-circuit checks.

pk := new(eonark.Pk)
if err := pk.Compile(&InnerCircuit{}); err != nil {
    panic(err)
}

assign := &InnerCircuit{/* ... fill witnesses ... */}
publics, _, proof, err := pk.Prove(assign)
if err != nil { panic(err) }

//optional: to check the correctness of the proof
vk := pk.Vk()
if err := vk.Verify(proof, publics); err != nil {
    panic("native verify failed")
}
```

### 2） Convert native proof into in-circuit witnesses
Use the conversion helpers provided in `recursion/funcs.go`:
```go
gnarkVK := vk.ToGnarkVerifyingKey()
gnarkProof := proof.ToGnarkProof()

cvk, _  := recursion.ValueOfVerifyingKey[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](gnarkVK)
cproof, _ := recursion.ValueOfProof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine](gnarkProof)
cwit, _  := recursion.ValueOfWitness[sw_bls12381.ScalarField](publicWitness)
```

### 3）Assemble outer circuit with FS transcript
```go
outer := new(struct {
    Proof        recursion.Proof[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine]
    VerifyingKey recursion.VerifyingKey[sw_bls12381.ScalarField, sw_bls12381.G1Affine, sw_bls12381.G2Affine] `gnark:"-"`
    InnerWitness recursion.Witness[sw_bls12381.ScalarField]
    FS           recursion.FSInputs `gnark:"-"`
})

outer.Proof        = cproof
outer.VerifyingKey = cvk
outer.InnerWitness = cwit
outer.FS           = buildFSInputs(gnarkVK, gnarkProof, publics) // helper provided
```

### 4）Compile and check constraints
```go
r1cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, outer)
if err != nil {
    panic(err)
}

fmt.Println("outer circuit constraints:", r1cs.GetNbConstraints())
```

## Quickstart
For a ready-to-run example, simply execute the bundled test:
```go
go test ./circuits/recursion -run Test_Recursion -v
```
Modify the InnerCircuit definition inside `circuit_test.go` and you can directly get the recursion proof.

