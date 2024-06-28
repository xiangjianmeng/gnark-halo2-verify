package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
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

//func ToElement1[T emulated.FieldParams](api frontend.API, input frontend.Variable) (emulated.Element[T], error) {
//	inputFiled, err := emulated.NewField[T](api)
//	if err != nil {
//		return emulated.Element[T]{}, err
//	}
//	inputBits := api.ToBinary(input, 256)
//	inputEle := inputFiled.FromBits(inputBits...)
//	return *inputEle, nil
//}

func Div128Hint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {

	//log.Println(inputs[0])
	//big128 := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(128), nil)
	//log.Println(big128)
	//big128f := new(big.Int).Sub(big128, big.NewInt(1))
	upper := new(big.Int).Div(inputs[0], big.NewInt(0).Lsh(big.NewInt(1), 128)) // input >> 128
	lower := new(big.Int).Mod(inputs[0], big.NewInt(0).Lsh(big.NewInt(1), 128)) // input & ((1 << 128) - 1)
	//log.Println(upper)
	//log.Println(lower)

	outputs[0] = upper
	outputs[1] = lower

	return nil
}

func ToElement[T emulated.FieldParams](api frontend.API, input frontend.Variable) (emulated.Element[T], error) {
	inputFiled, err := emulated.NewField[T](api)
	if err != nil {
		return emulated.Element[T]{}, err
	}

	results, err := api.Compiler().NewHint(Div128Hint, 2, input)
	if err != nil {
		return emulated.Element[T]{}, err
	}

	//log.Println("res:", results[0], results[1])
	// Decompose each part into binary representation
	upperBits := api.ToBinary(results[0], 128)
	lowerBits := api.ToBinary(results[1], 128)
	//log.Println(upperBits)
	//log.Println(lowerBits)

	// Concatenate the binary representations
	inputBits := append(lowerBits, upperBits...)

	//inputBits = api.ToBinary(input, 256)
	//log.Println(inputBits)
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

func extractAndConvert(input string) (string, string, error) {
	re := regexp.MustCompile(`bn256\.G1\((\w+),\s(\w+)\)`)

	matches := re.FindStringSubmatch(input)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid input format")
	}

	xStr := matches[1]
	yStr := matches[2]

	x10Str, err := hexToDecimalString(xStr)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode x: %v", err)
	}

	y10Str, err := hexToDecimalString(yStr)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode y: %v", err)
	}

	return x10Str, y10Str, nil
}

// Converts hex string to decimal string
func hexToDecimalString(hexStr string) (string, error) {
	// Strip leading "0x" if it exists
	hexStr = strings.TrimPrefix(hexStr, "0x")

	// Convert hex to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	// Convert bytes to big.Int
	bigInt := new(big.Int).SetBytes(bytes)

	// Convert big.Int to decimal string
	return bigInt.String(), nil
}
