package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func ValueOf(api frontend.API, a []frontend.Variable) []uints.U8 {
	length := 32 * len(a)
	var r = make([]uints.U8, length)
	//bts, err := api.Compiler().NewHint(toBytes, length, a)
	//if err != nil {
	//	panic(err)
	//}
	// TODO: add constraint which ensures that map back to
	//for i := range bts {
	//	r[i] = bts[i]
	//}

	return r[:]
}

func toBytes(m *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("input must be 1 elements")
	}
	nbLimbs := 32
	if len(outputs) != nbLimbs {
		return fmt.Errorf("output must be 8 elements")
	}
	if !inputs[1].IsUint64() {
		return fmt.Errorf("input must be 64 bits")
	}
	base := new(big.Int).Lsh(big.NewInt(1), uint(8))
	tmp := new(big.Int).Set(inputs[1])
	for i := 0; i < nbLimbs; i++ {
		outputs[i].Mod(tmp, base)
		tmp.Rsh(tmp, 8)
	}

	inputs[0].FillBytes(make([]byte, 32))

	return nil
}
