package main

import (
	"bytes"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/ethereum/go-ethereum/crypto"
)

type AggregatorCircuit struct {
	Proof      []fr.Element
	VerifyInst []fr.Element
	Aux        []fr.Element
	TargetInst []fr.Element `gnark:",public"`
}

func (circuit *AggregatorCircuit) Define(api frontend.API) error {
	buf := [43]fr.Element{}

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
		input := buf[i].Bytes()
		hashBuf.Write(input[:])
	}
	hashValHex := crypto.Keccak256Hash(hashBuf.Bytes())
	hashValBig := big.NewInt(0).SetBytes(hashValHex.Bytes())

	q, _ := big.NewInt(0).SetString(FrModulus, 10)
	hashMod := big.NewInt(0).Mod(hashValBig, q)
	//log.Println("hashMod: ", hashMod)

	input := uints.NewU8Array(hashBuf.Bytes())
	hashVar := uints.NewU8Array(hashValHex.Bytes())
	err := VerifyKeccak256(api, input, hashVar)
	if err != nil {
		log.Println(err)
		return err
	}

	buf[2].SetBigInt(hashMod)
	err = CalcVerifyCircuitLagrange(api, buf[:])
	if err != nil {
		return err
	}

	err = GetChallengesShPlonkCircuit(api, buf[:], circuit.Proof)
	if err != nil {
		return err
	}

	buf, err = VerifyProof1(api, circuit.Proof, circuit.Aux, buf)
	if err != nil {
		return err
	}
	buf, err = VerifyProof2(api, circuit.Proof, circuit.Aux, buf)
	if err != nil {
		return err
	}
	return nil
}
