package permissionless

import "github.com/consensys/gnark/frontend"

type Account struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
	Z frontend.Variable `gnark:",public"`
	W frontend.Variable `gnark:",public"`
}

func (me *Account) Define(api frontend.API) error {
	_, err := api.(frontend.Committer).Commit(me.X)
	return err
}
