package main

import (
	"github.com/eon-protocol/eonark"

	"github.com/consensys/gnark/frontend"
)

type Circuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
	Z frontend.Variable `gnark:",public"`
	W frontend.Variable `gnark:",public"`
}

func (me *Circuit) Define(api frontend.API) error {
	prod := api.Mul(me.X, me.Y, me.Z)
	api.AssertIsEqual(prod, me.W)
	_, err := api.(frontend.Committer).Commit(me.X)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	// logger.Disable()
	var pk eonark.Pk
	if err := pk.Compile(&Circuit{}); err != nil {
		panic(err)
	}
	vk := pk.Vk()
	publics, _, proof, err := pk.Prove(&Circuit{X: 1, Y: 1, Z: 1, W: 1})
	if err != nil {
		panic(err)
	}
	if err := vk.Verify(proof, publics); err != nil {
		panic(err)
	}

}
