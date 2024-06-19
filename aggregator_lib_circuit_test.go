package main

import (
	"log"
	"math/big"
	"testing"

	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/bn256"
)

func TestMsmSolve(t *testing.T) {
	assert := test.NewAssert(t)
	x, _ := new(big.Int).SetString("13534086339230182803823178260078315691269243572458753455438283544709107378988", 10)
	y, _ := new(big.Int).SetString("9053077977614827188269653632534212501565186534180282672519599630892718179094", 10)

	var blob []byte
	blob = append(blob, x.FillBytes(make([]byte, 32))...)
	blob = append(blob, y.FillBytes(make([]byte, 32))...)

	p := new(bn256.G1)
	_, err := p.Unmarshal(blob)
	assert.NoError(err)

	scalar, _ := new(big.Int).SetString("21018549926786911420919261871844456760738199621624594828144407595472474813958", 10)
	res := new(bn256.G1)
	res.ScalarMult(p, new(big.Int).SetBytes(scalar.FillBytes(make([]byte, 32))))

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

	var resCircuit = bn254.G1Affine{}
	xStr, yStr, _ := extractAndConvert(res.String())
	_, err = resCircuit.X.SetString(xStr)
	assert.NoError(err)
	_, err = resCircuit.Y.SetString(yStr)
	assert.NoError(err)
	assert.True(resCircuit.IsOnCurve())

	witnessCircuit := BN256MsmCircuit{
		G1Point: new(bn254.G1Affine),
		Scalar:  new(big.Int),
		Res:     new(bn254.G1Affine),
	}
	circuit := BN256MsmCircuit{
		G1Point: new(bn254.G1Affine),
		Scalar:  new(big.Int),
		Res:     new(bn254.G1Affine),
	}
	witnessCircuit.G1Point = &g10
	witnessCircuit.Scalar = scalar
	witnessCircuit.Res = &resCircuit

	err = test.IsSolved(&circuit, &witnessCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestSha2Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	input, succ := new(big.Int).SetString("21018549926786911420919261871844456760738199621624594828144407595472474813958", 10)
	assert.True(succ)

	inputBytes := input.FillBytes(make([]byte, 32))
	ethHashVal := sha256.Sum256(inputBytes)
	//keccakHashVal := crypto.Keccak256Hash(inputBytes)
	//log.Println(ethHashVal, keccakHashVal.Bytes())

	inputCircuit := uints.NewU8Array(inputBytes)
	hashValCircuit := uints.NewU8Array(ethHashVal[:])
	log.Println(inputCircuit)
	log.Println(hashValCircuit)
	witnessCircuit := Sha256Circuit{
		inputCircuit,
		hashValCircuit,
	}
	circuit := Sha256Circuit{
		InputValue: make([]uints.U8, len(inputBytes)),
		HashValue:  make([]uints.U8, len(ethHashVal[:])),
	}

	err := test.IsSolved(&circuit, &witnessCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestKeccak256Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	input, succ := new(big.Int).SetString("21018549926786911420919261871844456760738199621624594828144407595472474813958", 10)
	assert.True(succ)

	inputBytes := input.FillBytes(make([]byte, 32))
	keccakHashVal := crypto.Keccak256Hash(inputBytes)
	//log.Println(inputBytes)
	//log.Println(keccakHashVal.Bytes())

	inputCircuit := uints.NewU8Array(inputBytes)
	hashValCircuit := uints.NewU8Array(keccakHashVal.Bytes())
	//log.Println(inputCircuit)
	//log.Println(hashValCircuit)
	witnessCircuit := Keccak256Circuit{
		inputCircuit,
		hashValCircuit,
	}
	circuit := Keccak256Circuit{
		InputValue: make([]uints.U8, len(inputBytes)),
		HashValue:  make([]uints.U8, len(keccakHashVal.Bytes())),
	}

	err := test.IsSolved(&circuit, &witnessCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestCheckOnCurveCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	x, _ := new(big.Int).SetString("1", 10)
	y, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208581", 10)

	var g10 = bn254.G1Affine{}
	_ = g10.X.SetBigInt(x)
	_ = g10.Y.SetBigInt(y)
	assert.True(g10.IsOnCurve())

	var xEle fr.Element
	xEle.SetBigInt(x)
	var yEle fr.Element
	yEle.SetBigInt(y)
	witnessCircuit := CheckOnCurveCircuitVar{
		xEle,
		yEle,
	}
	circuit := CheckOnCurveCircuitVar{
		xEle,
		yEle,
	}

	err := test.IsSolved(&circuit, &witnessCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)
}
