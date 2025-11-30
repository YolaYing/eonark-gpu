//go:build icicle

package gpu

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	plonkbls12381 "github.com/consensys/gnark/backend/plonk/bls12-381"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"
)

type deviceInfo struct {
	Device   icicle_runtime.Device
	
	Streams []icicle_runtime.Stream

	G1Device struct {
		G1         icicle_core.DeviceSlice
		G1Lagrange icicle_core.DeviceSlice
	}

	N             int
	CosetTable    icicle_core.DeviceSlice // not Montgomery
	CosetTableRev icicle_core.DeviceSlice // not Montgomery

	// 大域Twiddles，用于scalingVector, 长度为n
	BigTwiddlesN    icicle_core.DeviceSlice // [1, w_N, w_N^2, ...]
	BigTwiddlesNRev icicle_core.DeviceSlice // 位反序版

	// —— 仅用于 CPU 回退时的“按需”Host 表（懒加载）
	onceCoset, onceBig         sync.Once
	hostCosetReg, hostCosetRev []fr.Element
	hostBigReg, hostBigRev     []fr.Element
	// 供构建 big 表使用的生成元（setup 时记下）
	bigW fr.Element

	mu sync.Mutex
}

// 同名结构，icicle 版多了 deviceInfo
type ProvingKey struct {
	Kzg         kzg.ProvingKey
	KzgLagrange kzg.ProvingKey
	Vk          *plonkbls12381.VerifyingKey
	deviceInfo  *deviceInfo
}

func WrapProvingKey(pk *plonkbls12381.ProvingKey) (*ProvingKey, error) {
	warmUpDevice()
	return &ProvingKey{
		Kzg:         pk.Kzg,
		KzgLagrange: pk.KzgLagrange,
		Vk:          pk.Vk,
		deviceInfo:  &deviceInfo{},
	}, nil
}

func (di *deviceInfo) ensureHostCosetTables(d0 *fft.Domain) ([]fr.Element, []fr.Element) {
	di.onceCoset.Do(func() {
		tab, _ := d0.CosetTable() // [1, s, s^2, ...] ，s = d1.FrMultiplicativeGen 由 gnark 内部管理
		di.hostCosetReg = tab
		di.hostCosetRev = make([]fr.Element, len(tab))
		copy(di.hostCosetRev, tab)
		fft.BitReverse(di.hostCosetRev)
	})
	return di.hostCosetReg, di.hostCosetRev
}

func (di *deviceInfo) ensureHostBigTables(n uint64) ([]fr.Element, []fr.Element) {
	di.onceBig.Do(func() {
		reg := make([]fr.Element, n)
		if n > 0 {
			reg[0].SetOne()
			if n > 1 {
				reg[1].Set(&di.bigW)
				for i := 2; i < int(n); i++ {
					reg[i].Mul(&reg[i-1], &di.bigW)
				}
			}
		}
		di.hostBigReg = reg
		di.hostBigRev = make([]fr.Element, len(reg))
		copy(di.hostBigRev, reg)
		fft.BitReverse(di.hostBigRev)
	})
	return di.hostBigReg, di.hostBigRev
}
