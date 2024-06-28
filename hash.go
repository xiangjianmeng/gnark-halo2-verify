package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
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

	for i := range res {
		uapi.ByteAssertEq(hashValue[i], res[i])
	}
	return nil
}

type Sha256Circuit struct {
	InputValue []uints.U8
	HashValue  []uints.U8
}

func (circuit Sha256Circuit) Define(api frontend.API) error {
	return VerifySha256(api, circuit.InputValue, circuit.HashValue)
}

func VerifySha256(
	api frontend.API,
	inputValue []uints.U8,
	hashValue []uints.U8,
) error {
	h, err := sha2.New(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}

	h.Write(inputValue)
	res := h.Sum()

	for i := range res {
		uapi.ByteAssertEq(hashValue[i], res[i])
	}
	return nil
}
