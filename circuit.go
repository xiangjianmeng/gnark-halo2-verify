package main

import (
	"bytes"
	"log"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/ethereum/go-ethereum/crypto"
)

type Keccak256Circuit struct {
	InputValue []uints.U8
	HashValue  []uints.U8
}

func (circuit Keccak256Circuit) Define(api frontend.API) error {
	return VerifyKeccak256(api, circuit.InputValue, circuit.HashValue)
}

func VerifyKeccak256(
	api frontend.API,
	inputValue []uints.U8,
	hashValue []uints.U8,
) error {
	h, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}

	h.Write(inputValue)
	res := h.Sum()

	for i := range hashValue {
		uapi.ByteAssertEq(hashValue[i], res[i])
	}
	return nil
}

type AggregatorCircuit struct {
	Proof      []frontend.Variable
	VerifyInst []frontend.Variable
	Aux        []frontend.Variable
	TargetInst []frontend.Variable `gnark:",public"`
}

func (circuit *AggregatorCircuit) Define(api frontend.API) error {
	buf := [43]frontend.Variable{}

	// step 0: calc real verify instance with keccak
	var bufLen = 0
	for i := 0; i < len(circuit.TargetInst); i++ {
		buf[bufLen] = circuit.TargetInst[i]
		bufLen++
	}

	for i := 0; i < len(circuit.VerifyInst); i++ {
		buf[bufLen] = circuit.VerifyInst[i]
		bufLen++
	}

	var hashBuf bytes.Buffer
	for i := 0; i < bufLen; i++ {
		tmp := buf[i].(*big.Int)
		hashBuf.Write(tmp.FillBytes(make([]byte, 32)))
	}
	hashValHex := crypto.Keccak256Hash(hashBuf.Bytes())
	hashValBig := big.NewInt(0).SetBytes(hashValHex.Bytes())
	log.Println("eth Keccak256Hash", hashBuf.Bytes(), hashValBig, hashValHex.String())

	q, _ := big.NewInt(0).SetString(FrModulus, 10)
	hashMod := big.NewInt(0).Mod(hashValBig, q)
	log.Println("hashMod: ", hashMod)

	input := uints.NewU8Array(hashBuf.Bytes())
	hashVar := uints.NewU8Array(hashValHex.Bytes())
	err := VerifyKeccak256(api, input, hashVar)
	if err != nil {
		log.Println(err)
		return err
	}

	buf[2] = frontend.Variable(hashMod)
	err = calcVerifyCircuitLagrange(api, buf[:])
	if err != nil {
		return err
	}

	return nil
}
