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
	for i := 0; i < 43; i++ {
		buf[i] = new(big.Int).SetUint64(0)
	}

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

	//var hashBuf bytes.Buffer
	//for i := 0; i < bufLen; i++ {
	//	fpTmp, err := new(fp.Element).SetInterface(buf[i])
	//	if err != nil {
	//		return err
	//	}
	//	input := fpTmp.Bytes()
	//	hashBuf.Write(input[:])
	//}
	//
	//hashValHex := crypto.Keccak256Hash(hashBuf.Bytes())
	//hashValBig := big.NewInt(0).SetBytes(hashValHex.Bytes())
	//log.Println("hashValBig", hashValBig)
	//
	//input := uints.NewU8Array(hashBuf.Bytes())
	//hashVar := uints.NewU8Array(hashValHex.Bytes())
	//err := VerifyKeccak256(api, input, hashVar)
	//if err != nil {
	//	log.Println(err)
	//	return err
	//}

	hashValBig, err := VerifyInstanceHash(api, buf[:bufLen])
	if err != nil {
		log.Println(err)
		return err
	}

	//q, _ := big.NewInt(0).SetString(FrModulus, 10)
	//hashMod := big.NewInt(0).Mod(hashValBig, q)
	hashMod := mod(api, hashValBig)
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

func VerifyInstanceHash(api frontend.API, inputs []frontend.Variable) (frontend.Variable, error) {
	length := 32 * (len(inputs) + 1)
	result, err := api.Compiler().NewHint(Keccak256Hint, 1+length, inputs...)
	if err != nil {
		return nil, err
	}

	//scalarBits := api.ToBinary(result[0], 256)
	binaryF, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, err
	}

	var hashU8Array, inputU8Array []uints.U8
	for i := 1; i < 33; i++ {
		hashU8Array = append(hashU8Array, binaryF.ByteValueOf(result[i]))
	}

	for i := 33; i < length+1; i++ {
		inputU8Array = append(inputU8Array, binaryF.ByteValueOf(result[i]))
	}

	//input := uints.NewU8Array(result[0].(*big.Int).Bytes())
	//hashVar := uints.NewU8Array(result[0].(*big.Int).Bytes())
	err = VerifyKeccak256(api, inputU8Array, hashU8Array)
	log.Println(err)
	return PackUInt8Variables(api, result[1:33]...), err
	//return result[0], err
}

func Keccak256Hint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	var hashBuf bytes.Buffer
	for i := 0; i < len(inputs); i++ {
		fpEle := new(fp.Element).SetBigInt(inputs[i])
		input := fpEle.Bytes()
		hashBuf.Write(input[:])
	}
	hashValHex := crypto.Keccak256Hash(hashBuf.Bytes())
	hashValBig := big.NewInt(0).SetBytes(hashValHex.Bytes())
	//log.Println("hashBuf.Bytes()", hashBuf.Bytes())
	//log.Println("hashValBig", hashValBig)
	//log.Println("hashValHex", hashValHex.Bytes())

	//results[0] = big.NewInt(0).SetBytes(hashBuf.Bytes())
	results[0] = hashValBig
	i := 1
	for _, bigByte := range hashValHex.Bytes() {
		results[i] = new(big.Int).SetBytes([]byte{bigByte})
		i++
	}

	for _, bigByte := range hashBuf.Bytes() {
		results[i] = new(big.Int).SetBytes([]byte{bigByte})
		i++
	}

	return nil
}
