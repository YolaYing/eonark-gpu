//go:build icicle

package gpu

import (
	"github.com/consensys/gnark/backend"
	plonkbls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bls12-381"
)

// 你已有的 GPU 逻辑在 patch_gpu.go 里定义了 unexported 的 prove(...)
// 这里导出一个同签名的 Prove 供路由器调用。
func Prove(spr *cs.SparseR1CS, pk *ProvingKey, w witness.Witness, opts ...backend.ProverOption) (*plonkbls12381.Proof, error) {
	return prove(spr, pk, w, opts...)
}
