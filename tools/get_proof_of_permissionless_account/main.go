package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/eon-protocol/eonark"
	"github.com/eon-protocol/eonark/accounts/permissionless"
)

func main() {
	var pk eonark.Pk
	if err := pk.Compile(&permissionless.Account{}); err != nil {
		log.Fatalln(err)
	}
	if len(os.Args) != 5 {
		log.Fatalln("usage:", os.Args[0], "<x>", "<y>", "<z>", "<w>")
	}
	var x, y, z, w fr.Element
	if err := bls12381.NewDecoder(hex.NewDecoder(strings.NewReader(os.Args[1]))).Decode(&x); err != nil {
		log.Fatalln(err)
	}
	if err := bls12381.NewDecoder(hex.NewDecoder(strings.NewReader(os.Args[2]))).Decode(&y); err != nil {
		log.Fatalln(err)
	}
	if err := bls12381.NewDecoder(hex.NewDecoder(strings.NewReader(os.Args[3]))).Decode(&z); err != nil {
		log.Fatalln(err)
	}
	if err := bls12381.NewDecoder(hex.NewDecoder(strings.NewReader(os.Args[4]))).Decode(&w); err != nil {
		log.Fatalln(err)
	}
	_, _, proof, err := pk.Prove(&permissionless.Account{X: x, Y: y, Z: z, W: w})
	if err != nil {
		log.Fatalln(err)
	}
	enc := hex.NewEncoder(os.Stdout)
	if _, err := proof.WriteTo(enc); err != nil {
		log.Fatalln(err)
	}
	fmt.Println()
}
