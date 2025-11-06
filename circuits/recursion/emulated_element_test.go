package recursion

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"

	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

type demoCircuit struct {
	S   sw_bls12381.Scalar
	Pub frontend.Variable `gnark:",public"`
}

// 一个简单的电路测试下Pub == S + 1， 其中Pub是普通的frontend的element
func (c *demoCircuit) Define(api frontend.API) error {

	f, err := emulated.NewField[sw_bls12381.ScalarField](api)
	if err != nil {
		return err
	}
	one := f.One()
	sPlus1 := f.Add(&c.S, one)

	// 普通 frontend.Variable(普通Fr元素) -> emulated scalar element
	var fp sw_bls12381.ScalarField
	nbits := fp.Modulus().BitLen()
	bits := bits.ToBinary(api, c.Pub, bits.WithNbDigits(nbits))
	pubE := f.FromBits(bits...)

	f.AssertIsEqual(sPlus1, pubE)
	return nil
}

func Test_Emulated_Scalar_and_G1(t *testing.T) {
	assert := test.NewAssert(t)

	c := new(demoCircuit)
	_, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, c)
	assert.NoError(err)

	var s fr.Element
	s.SetUint64(42)
	var one fr.Element
	one.SetOne()
	var sPlus1 fr.Element
	sPlus1.Add(&s, &one)

	bs := new(big.Int)
	s.BigInt(bs)

	// ---- 赋值并求解 ----
	assign := &demoCircuit{
		S:   emulated.ValueOf[sw_bls12381.ScalarField](bs), // emulated scalar field element
		Pub: sPlus1,                                        // 这里就是算完的普通frontend.Variable(普通Fr元素)
	}

	assert.SolvingSucceeded(c, assign, test.WithCurves(ecc.BLS12_381))
}
