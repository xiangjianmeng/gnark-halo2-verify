package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
)

func PackUInt8BigInt(inputs ...*big.Int) *big.Int {
	res := inputs[0]
	for _, input := range inputs[1:] {
		res = new(big.Int).Mul(res, new(big.Int).Exp(big.NewInt(2), big.NewInt(8), nil))
		res = new(big.Int).Add(res, input)
	}
	return res
}

func PackUInt8Variables(api frontend.API, inputs ...frontend.Variable) frontend.Variable {
	res := inputs[0]
	for _, input := range inputs[1:] {
		res = api.Mul(res, new(big.Int).Exp(big.NewInt(2), big.NewInt(8), nil))
		res = api.Add(res, input)
	}
	return res
}

func PackUInt128Variables(api frontend.API, inputs ...frontend.Variable) frontend.Variable {
	res := inputs[0]
	for _, input := range inputs[1:] {
		res = api.Mul(res, new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil))
		res = api.Add(res, input)
	}
	return res
}

func ToElement[T emulated.FieldParams](api frontend.API, input frontend.Variable) (emulated.Element[T], error) {
	inputFiled, err := emulated.NewField[T](api)
	if err != nil {
		return emulated.Element[T]{}, err
	}
	inputBits := api.ToBinary(input, 256)
	inputEle := inputFiled.FromBits(inputBits...)
	return *inputEle, nil
}

func ToPoint[T emulated.FieldParams](api frontend.API, point [2]frontend.Variable) (sw_emulated.AffinePoint[T], error) {
	x, err := ToElement[T](api, point[0])
	if err != nil {
		return sw_emulated.AffinePoint[T]{}, err
	}
	y, err := ToElement[T](api, point[1])
	if err != nil {
		return sw_emulated.AffinePoint[T]{}, err
	}

	return sw_emulated.AffinePoint[T]{
		X: x,
		Y: y,
	}, nil
}
