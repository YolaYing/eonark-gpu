package eonark

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/bits"
	"net/http"
	"os"
	"path"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/schollz/progressbar/v3"
)

var permutation = sync.OnceValue(func() *poseidon2.Permutation {
	return poseidon2.NewPermutationWithSeed(HASH_T, HASH_RF, HASH_RP, "PLACEHOLDER_PROJECT_NAME_PLACEHOLDER_POSEIDON2_HASH_SEED")
})

func DecomposeG1(val bls12381.G1Affine) [2][2]fr.Element {
	var ixq, ixm, iyq, iym big.Int
	var exq, exm, eyq, eym fr.Element
	val.X.BigInt(&ixq)
	val.Y.BigInt(&iyq)
	ixq.DivMod(&ixq, fr.Modulus(), &ixm)
	iyq.DivMod(&iyq, fr.Modulus(), &iym)
	exq.SetBigInt(&ixq)
	exm.SetBigInt(&ixm)
	eyq.SetBigInt(&iyq)
	eym.SetBigInt(&iym)
	return [2][2]fr.Element{{exq, exm}, {eyq, eym}}
}

func HashG1(val bls12381.G1Affine) fr.Element {
	decompose := DecomposeG1(val)
	x := HashCompress(decompose[0][0], decompose[0][1])
	y := HashCompress(decompose[1][0], decompose[1][1])
	return HashCompress(x, y)
}

func HashCompress(x, y fr.Element) fr.Element {
	vars := [2]fr.Element{x, y}
	if err := permutation().Permutation(vars[:]); err != nil {
		log.Fatalln(err)
	}
	var ret fr.Element
	ret.Add(&vars[1], &y)
	return ret
}

func HashSum(val ...fr.Element) fr.Element {
	var ret fr.Element
	for _, v := range val {
		ret = HashCompress(ret, v)
	}
	return ret
}

func read_proving_key(sc, sl int) (pk kzg.ProvingKey, lk kzg.ProvingKey, err error) {
	var dir string
	dir, err = os.UserCacheDir()
	if err != nil {
		return
	}
	dir = path.Join(dir, "eonark")
	if err = os.MkdirAll(dir, os.ModePerm); err != nil {
		return
	}
	logsl := bits.TrailingZeros(uint(sl))
	if bits.OnesCount(uint(sl)) != 1 {
		err = errors.New("sl should be power of 2")
		return
	}
	if logsl >= len(SRS_LK_HASH) {
		err = errors.New("sl too large")
		return
	}
	pathpk := path.Join(dir, "SRS.PK.BIN")
	pathlk := path.Join(dir, fmt.Sprintf("SRS.LK.%v.BIN", logsl))
	for i := 0; i < 3; i++ {
		if i > 0 {
			log.Printf("reloading srs ...\n")
		}
		bytepk, errpk := os.ReadFile(pathpk)
		hashpk := sha256.Sum256(bytepk)
		if errpk != nil || hashpk != SRS_PK_HASH {
			if err = download_srs_cache(pathpk); err != nil {
				return
			}
			continue
		}
		buf := make([]byte, 8)
		var g1 bls12381.G1Affine
		readerpk := bytes.NewReader(bytepk)
		pk.G1 = make([]bls12381.G1Affine, 0, sc)
		for n := 0; n < sc; n++ {
			for i := 0; i < 6; i++ {
				if _, err = io.ReadFull(readerpk, buf); err != nil {
					return
				}
				g1.X[i] = binary.BigEndian.Uint64(buf)
			}
			for i := 0; i < 6; i++ {
				if _, err = io.ReadFull(readerpk, buf); err != nil {
					return
				}
				g1.Y[i] = binary.BigEndian.Uint64(buf)
			}
			pk.G1 = append(pk.G1, g1)
		}
		bytelk, errlk := os.ReadFile(pathlk)
		hashlk := sha256.Sum256(bytelk)
		if errlk != nil || hashlk != SRS_LK_HASH[logsl] {
			log.Println(errlk, hex.EncodeToString(hashlk[:]))
			lk.G1, err = generate_srs_lk(pathlk, pk.G1[:sl], logsl)
			return
		}
		readerlk := bytes.NewReader(bytelk)
		lk.G1 = make([]bls12381.G1Affine, 0, sl)
		for n := 0; n < sl; n++ {
			for i := 0; i < 6; i++ {
				if _, err = io.ReadFull(readerlk, buf); err != nil {
					return
				}
				g1.X[i] = binary.BigEndian.Uint64(buf)
			}
			for i := 0; i < 6; i++ {
				if _, err = io.ReadFull(readerlk, buf); err != nil {
					return
				}
				g1.Y[i] = binary.BigEndian.Uint64(buf)
			}
			lk.G1 = append(lk.G1, g1)
		}
		return
	}
	return
}

func download_srs_cache(pathpk string) error {
	resp, err := http.Get(SRS_DOWNLOAD_URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	bar := progressbar.DefaultBytes(resp.ContentLength, "downloading srs ...")
	if _, err := io.Copy(io.MultiWriter(&buf, bar), resp.Body); err != nil {
		return err
	}
	return os.WriteFile(pathpk, buf.Bytes(), 0o644)
}

func generate_srs_lk(pathlk string, g1 []bls12381.G1Affine, logsl int) ([]bls12381.G1Affine, error) {
	lk, err := kzg.ToLagrangeG1(g1)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, xy := range lk {
		for _, v := range xy.X {
			if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
				return nil, err
			}
		}
		for _, v := range xy.Y {
			if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
				return nil, err
			}
		}
	}
	if err := os.WriteFile(pathlk, buf.Bytes(), 0o644); err != nil {
		return nil, err
	}
	return lk, nil
}
