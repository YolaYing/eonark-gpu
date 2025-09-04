package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/eon-protocol/eonark"
)

func main() {
	file, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalln(err)
	}
	sc := len(file) / 96
	if sc*96 != len(file) {
		log.Fatalln("invalid ck file;", "size:", len(file))
	}
	ck, err := eonark.ParseProvingKey(file, sc)
	if err != nil {
		log.Fatalln(err)
	}
	for i := 0; (1 << i) <= len(ck); i++ {
		lk, err := kzg.ToLagrangeG1(ck[:1<<i])
		if err != nil {
			log.Fatalln(err)
		}
		hasher := sha256.New()
		for _, xy := range lk {
			for _, v := range xy.X {
				if err := binary.Write(hasher, binary.BigEndian, v); err != nil {
					log.Fatalln(err)
				}
			}
			for _, v := range xy.Y {
				if err := binary.Write(hasher, binary.BigEndian, v); err != nil {
					log.Fatalln(err)
				}
			}
		}
		sum := hasher.Sum(nil)
		fmt.Println("sha256", "(", "SRS.LK", "[", i, "]", ")", "=", hex.EncodeToString(sum[:]))
	}
}
