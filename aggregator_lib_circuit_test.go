package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"log"
	"math/big"
	"testing"
)

func TestMsmSolve(t *testing.T) {
	assert := test.NewAssert(t)
	//p, err := newCurvePoint(getData(input, 0, 64))
	x, succeed := new(big.Int).SetString("13534086339230182803823178260078315691269243572458753455438283544709107378988", 10)
	assert.True(succeed)
	y, succeed := new(big.Int).SetString("9053077977614827188269653632534212501565186534180282672519599630892718179094", 10)
	assert.True(succeed)

	var blob []byte
	blob = append(blob, x.FillBytes(make([]byte, 32))...)
	blob = append(blob, y.FillBytes(make([]byte, 32))...)

	p := new(bn256.G1)
	_, err := p.Unmarshal(blob)
	assert.NoError(err)
	res := new(bn256.G1)
	scalar, succeed := new(big.Int).SetString("9053077977614827188269653632534212501565186534180282672519599630892718179094", 10)
	assert.True(succeed)
	res.ScalarMult(p, new(big.Int).SetBytes(scalar.FillBytes(make([]byte, 32))))
	log.Println(res.String())

	var g10 = bn254.G1Affine{}
	_, err = g10.X.SetString(x.String())
	if err != nil {
		panic(err)
	}
	_, err = g10.Y.SetString(y.String())
	if err != nil {
		panic(err)
	}
	assert.True(g10.IsOnCurve())

	witnessCircuit := BN256MsmCircuit{}
	circuit := BN256MsmCircuit{
		G1Point: new(bn254.G1Affine),
		Scalar:  new(big.Int),
		Res:     new(bn254.G1Affine),
	}
	witnessCircuit.G1Point = &g10
	witnessCircuit.Scalar = scalar
	var resCircuit = bn254.G1Affine{}
	xStr, yStr, _ := extractAndConvert(res.String())
	log.Println("xStr, yStr", xStr, yStr)
	_, err = resCircuit.X.SetString(xStr)
	if err != nil {
		panic(err)
	}
	_, err = resCircuit.Y.SetString(yStr)
	if err != nil {
		panic(err)
	}
	log.Println("resCircuit", resCircuit.String())
	//witnessCircuit.Res = &resCircuit

	err = test.IsSolved(&circuit, &witnessCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)
}
