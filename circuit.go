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
	//log.Println("GetChallengesShPlonkCircuit", "\n", buf[0], "\n", buf[1], "\n", buf[2], "\n", buf[3], "\n", buf[4], "\n", buf[5], "\n", buf[6], "\n", buf[7], "\n", buf[8], "\n", buf[9])

	buf, err = VerifyProof1(api, circuit.Proof, circuit.Aux, buf)
	if err != nil {
		return err
	}

	buf, err = VerifyProof2(api, circuit.Proof, circuit.Aux, buf)
	if err != nil {
		return err
	}

	buf, err = VerifyProof3(api, circuit.Proof, circuit.Aux, buf)
	if err != nil {
		return err
	}

	err = VerifyNotZero(api, buf[10])
	if err != nil {
		return err
	}
	err = VerifyNotZero(api, buf[11])
	if err != nil {
		return err
	}
	err = VerifyNotZero(api, buf[12])
	if err != nil {
		return err
	}
	err = VerifyNotZero(api, buf[13])
	if err != nil {
		return err
	}

	witnessCircuit := BN256PairingCircuit{}
	witnessCircuit.FillVerifyCircuitsG1(
		buf[10], buf[11], buf[12], buf[13],
	)
	witnessCircuit.FillVerifyCircuitsG2()
	err = VerifyBN256Pairing(api, witnessCircuit.G1Points[:], witnessCircuit.G2Points[:])
	return err
}
