package main

import (
	"bytes"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
	"log"
	"math/big"
	//"github.com/consensys/gnark/std/math/bits"
	"github.com/ethereum/go-ethereum/crypto"
)

type Keccak256Constraints struct {
	InputValue []uints.U8
	HashValue  []uints.U8
}

func (circuit Keccak256Constraints) Define(api frontend.API) error {
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
		bufBytes := convertVariableToBytes(api, buf[i])
		hashBuf.Write(new(big.Int).SetBytes(bufBytes).FillBytes(make([]byte, 32)))
	}

	hashVal := crypto.Keccak256Hash(hashBuf.Bytes())
	hashVar := uints.NewU8Array(hashVal.Bytes())
	log.Println(new(big.Int).SetBytes(hashVal.Bytes()).String())

	input := uints.NewU8Array(hashBuf.Bytes())
	err := VerifyKeccak256(api, input, hashVar)
	if err != nil {
		log.Println(err)
		return err
	}

	buf[2] = bytesToFrontendVariable(api, hashVal.Bytes())

	return nil
}

func bytesToFrontendVariable(api frontend.API, bytes []byte) frontend.Variable {
	binary := make([]frontend.Variable, len(bytes)*8)
	for i, b := range bytes {
		for j := 0; j < 8; j++ {
			val, _ := api.Compiler().ConstantValue((b >> j) & 1)
			binary[i*8+j] = *val
		}
	}
	return api.FromBinary(binary...)
}

// convertBitsToBytes converts a binary representation to a byte array
func convertVariableToBytes(api frontend.API, variable frontend.Variable) []byte {
	binary := api.ToBinary(variable, 256)
	return binaryToBytes(binary)
}

func binaryToBytes(binary []frontend.Variable) []byte {
	byteCount := (len(binary) + 7) / 8
	bytes := make([]byte, byteCount)

	for i := 0; i < len(binary); i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		if binary[i] == 1 {
			bytes[byteIndex] |= 1 << bitIndex
		}
	}

	return bytes
}
