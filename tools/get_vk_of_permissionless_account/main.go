package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/eon-protocol/eonark"
	"github.com/eon-protocol/eonark/accounts/permissionless"
)

func main() {
	var pk eonark.Pk
	if err := pk.Compile(&permissionless.Account{}); err != nil {
		log.Fatalln(err)
	}
	vk := pk.Vk()
	enc := hex.NewEncoder(os.Stdout)
	if _, err := vk.WriteTo(enc); err != nil {
		log.Fatalln(err)
	}
	fmt.Println()
}
