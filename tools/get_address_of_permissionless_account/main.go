package main

import (
	"fmt"
	"log"

	"github.com/eon-protocol/eonark"
	"github.com/eon-protocol/eonark/accounts/permissionless"
)

func main() {
	var pk eonark.Pk
	if err := pk.Compile(&permissionless.Account{}); err != nil {
		log.Fatalln(err)
	}
	vk := pk.Vk()
	addr := vk.Address()
	fmt.Println(addr.Text(16))
}
