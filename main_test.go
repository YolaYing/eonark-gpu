package eonark

import (
	"log"
	"testing"
)

func TestXxx(t *testing.T) {
	n := 1 << 21
	_, _, e := read_proving_key(n, n)
	// log.Println(x)
	// log.Println(y)
	log.Println(e)
}
