package verify

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"gnark-halo2-verify/circuit"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto"
)

type Aggregator struct {
	Proof       []*big.Int
	VerifyInst  []*big.Int
	Aux         []*big.Int
	TargetInst  []*big.Int
	ProgramHash []*big.Int
}

func (agg *Aggregator) Define(api frontend.API) error {
	hash := circuit.PackUInt64BigInt(agg.TargetInst...)
	api.AssertIsEqual(hash, agg.ProgramHash)

	buf := [43]*big.Int{}
	for i := 0; i < 43; i++ {
		buf[i] = new(big.Int).SetUint64(0)
	}

	// step 0: calc real verify instance with keccak
	var bufLen = 0
	for i := 0; i < len(agg.TargetInst); i++ {
		buf[bufLen] = agg.TargetInst[i]
		bufLen++
	}

	for i := 0; i < len(agg.VerifyInst); i++ {
		buf[bufLen] = agg.VerifyInst[i]
		bufLen++
	}

	hashMod := InstanceHash(buf[:bufLen])

	buf[2] = hashMod

	//	err = CalcVerifyCircuitLagrange(api, buf[:])
	//	if err != nil {
	//		return err
	//	}
	//
	//	err = GetChallengesShPlonkCircuit(api, buf[:], circuit.Proof)
	//	if err != nil {
	//		return err
	//	}
	//
	//	buf, err = VerifyProof1(api, circuit.Proof, circuit.Aux, buf)
	//	if err != nil {
	//		return err
	//	}
	//
	//	buf, err = VerifyProof2(api, circuit.Proof, circuit.Aux, buf)
	//	if err != nil {
	//		return err
	//	}
	//
	//	buf, err = VerifyProof3(api, circuit.Proof, circuit.Aux, buf)
	//	if err != nil {
	//		return err
	//	}
	//
	//	for i := 10; i < 14; i++ {
	//		err = VerifyNotZero(api, buf[i])
	//		if err != nil {
	//			return err
	//		}
	//	}
	//
	//	G1Points, err := FillVerifyCircuitsG1(api, buf[10], buf[11], buf[12], buf[13])
	//	if err != nil {
	//		return err
	//	}
	//	G2Points := FillVerifyCircuitsG2()
	//	err = VerifyBN256Pairing(api, G1Points[:], G2Points[:])
	//	return err
	return nil
}

func InstanceHash(inputs []*big.Int) *big.Int {
	var hashBuf bytes.Buffer
	for i := 0; i < len(inputs); i++ {
		fpEle := new(fp.Element).SetBigInt(inputs[i])
		input := fpEle.Bytes()
		hashBuf.Write(input[:])
	}
	hashValHex := crypto.Keccak256Hash(hashBuf.Bytes())
	hashBig := new(big.Int).SetBytes(hashValHex.Bytes())
	hashMod := new(big.Int).Mod(hashBig, circuit.MODULUS)

	return hashMod
}
