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
	return poseidon2.NewPermutationWithSeed(HASH_T, HASH_RF, HASH_RP, "EON_POSEIDON2_HASH_SEED")
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

func ParseProvingKey(bytepk []byte, size int) (val []bls12381.G1Affine, err error) {
	var g1 bls12381.G1Affine
	buf := make([]byte, 8)
	reader := bytes.NewReader(bytepk)
	val = make([]bls12381.G1Affine, 0, size)
	for n := 0; n < size; n++ {
		for i := 0; i < 6; i++ {
			if _, err = io.ReadFull(reader, buf); err != nil {
				return
			}
			g1.X[i] = binary.BigEndian.Uint64(buf)
		}
		for i := 0; i < 6; i++ {
			if _, err = io.ReadFull(reader, buf); err != nil {
				return
			}
			g1.Y[i] = binary.BigEndian.Uint64(buf)
		}
		val = append(val, g1)
	}
	return
}

func ReadProvingKey(sc, sl int) (ck kzg.ProvingKey, lk kzg.ProvingKey, err error) {
	logsl := bits.TrailingZeros(uint(sl))
	if bits.OnesCount(uint(sl)) != 1 || logsl >= len(SRS_LK_HASH) {
		err = errors.New("invalid sl")
		return
	}
	pathck := path.Join(DATA_CACHE_DIR, "SRS.CK.BIN")
	pathlk := path.Join(DATA_CACHE_DIR, fmt.Sprintf("SRS.LK.%v.BIN", logsl))
	byteck, errck := os.ReadFile(pathck)
	sumck := sha256.Sum256(byteck)
	sumckstr := hex.EncodeToString(sumck[:])
	if errck != nil || sumckstr != SRS_CK_HASH {
		log.Println("local srsck cache not found; downloading ...")
		if byteck, err = download_srs_ck(pathck); err != nil {
			return
		}
	}
	if ck.G1, err = ParseProvingKey(byteck, sc); err != nil {
		return
	}
	bytelk, errlk := os.ReadFile(pathlk)
	sumlk := sha256.Sum256(bytelk)
	sumlkstr := hex.EncodeToString(sumlk[:])
	if errlk != nil || sumlkstr != SRS_LK_HASH[logsl] {
		log.Println("local srslk cache not found; generating ...")
		lk.G1, err = generate_srs_lk(pathlk, ck.G1[:sl])
		return
	}
	if lk.G1, err = ParseProvingKey(bytelk, sl); err != nil {
		return
	}
	return
}

func download_srs_ck(pathck string) ([]byte, error) {
	resp, err := http.Get(SRS_DOWNLOAD_URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	bar := progressbar.DefaultBytes(resp.ContentLength, "Downloading SRSCK")
	if _, err := io.Copy(io.MultiWriter(&buf, bar), resp.Body); err != nil {
		return nil, err
	}
	byteck := buf.Bytes()
	return byteck, os.WriteFile(pathck, byteck, 0o644)
}

func generate_srs_lk(pathlk string, g1 []bls12381.G1Affine) ([]bls12381.G1Affine, error) {
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
