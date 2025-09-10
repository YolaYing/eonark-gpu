# Hasher Circuit (Poseidon2 on BLS12-381)

This package implements **Poseidon2-based hash functions** for both:
- **In-circuit usage**
- **Native usage**

## Package Overview

### Hard-coded Poseidon2 parameters settings:
- `vars.go`  
  Centralized Poseidon2 parameters (`WIDTH`, `ROUND_FULL`, `ROUND_PARTIAL`, `SEED`).

### Native usage
- `funcs.go`  
  Native equivalents of the circuit gadgets, for off-chain preprocessing and testing.

### In-circuit usage
- `circuit.go`  
  In-circuit Poseidon2 permutation and derived gadgets (`Compress`, `HashSumVars`, `HashG1Vars`).
- `hints.go`  
  Generic decomposition hint (`HintDecomposeMod_LE`) to split coordinates modulo the field modulus.

### Testing
- `circuit_test.go`  
  Unit tests cross-checking native vs circuit behavior.

## Parameter Policy
Poseidon2 parameters are **hard-coded** in [`vars.go`](vars.go):

```go
const WIDTH       = 2
const ROUND_FULL  = 8
const ROUND_PARTIAL = 56
const USESEED     = true
const SEED        = "PLACEHOLDER_PROJECT_NAME_PLACEHOLDER_POSEIDON2_HASH_SEED"
```

## Usage

### Native (off-circuit)
```go
import "github.com/eon-protocol/eonark/circuits/hasher"

out := hasher.HashCompress(x, y)
sum := hasher.HashSum(vals...)
g1h := hasher.HashG1(point)
addr := hasher.Address(vk) // requires eonark.Vk
```

### In-circuit
```go
import "github.com/eon-protocol/eonark/circuits/hasher"

func (c *MyCircuit) Define(api frontend.API) error {
    h, _ := hasher.NewPoseidon2FromParameters(api)

    // Compress two field elements
    z := h.HashCompressVars(x, y)

    // Fold multiple inputs
    acc := h.HashSumVars(a, b, c)

    // Hash a decomposed G1 point
    g := hasher.G1DecomposedVars{XQ: xq, XM: xm, YQ: yq, YM: ym}
    out := h.HashG1Vars(g)

    api.AssertIsEqual(z, acc) // example constraint
    return nil
}
```

## Testing Script
Run the package tests:
```go
go test ./circuits/hasher -v
```


