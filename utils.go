package main

import (
	"github.com/consensys/gnark/frontend"
	"math/big"
)

func PackUInt8Variables(api frontend.API, inputs ...frontend.Variable) frontend.Variable {
	res := inputs[0]
	for _, input := range inputs[1:] {
		res = api.Mul(res, new(big.Int).Exp(big.NewInt(2), big.NewInt(8), nil))
		res = api.Add(res, input)
	}
	return res
}
