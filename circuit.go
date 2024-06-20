package main

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"log"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/ethereum/go-ethereum/crypto"
)

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
		fpTmp, _ := new(fp.Element).SetInterface(buf[i])
		input := fpTmp.Bytes()
		hashBuf.Write(input[:])
	}
	hashValHex := crypto.Keccak256Hash(hashBuf.Bytes())
	hashValBig := big.NewInt(0).SetBytes(hashValHex.Bytes())
	log.Println("hashValBig", hashValBig)

	input := uints.NewU8Array(hashBuf.Bytes())
	hashVar := uints.NewU8Array(hashValHex.Bytes())
	err := VerifyKeccak256(api, input, hashVar)
	if err != nil {
		log.Println(err)
		return err
	}

	q, _ := big.NewInt(0).SetString(FrModulus, 10)
	hashMod := big.NewInt(0).Mod(hashValBig, q)
	log.Println("hashMod: ", hashMod)
	buf[2] = hashMod

	err = CalcVerifyCircuitLagrange(api, buf[:])
	if err != nil {
		return err
	}

	log.Println("CalcVerifyCircuitLagrange", buf[0], buf[1], buf[2])

	err = GetChallengesShPlonkCircuit(api, buf[:], circuit.Proof)
	if err != nil {
		return err
	}

	log.Println("GetChallengesShPlonkCircuit", buf[0], buf[1], buf[2])

	var proofVar = make([]frontend.Variable, len(circuit.Proof))
	for i := 0; i < len(circuit.Proof); i++ {
		proofVar[i] = circuit.Proof[i]
	}
	var auxVar = make([]frontend.Variable, len(circuit.Aux))
	for i := 0; i < len(circuit.Aux); i++ {
		auxVar[i] = circuit.Aux[i]
	}
	var bufVar [len(buf)]frontend.Variable
	for i := 0; i < len(buf); i++ {
		bufVar[i] = buf[i]
	}

	resBuf, err := VerifyProof1(api, proofVar, auxVar, bufVar)
	if err != nil {
		return err
	}
	resBuf, err = VerifyProof2(api, proofVar, auxVar, resBuf)
	if err != nil {
		return err
	}
	return nil
}
