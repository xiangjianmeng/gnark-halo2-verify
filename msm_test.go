package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"log"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

func TestMultiScalarMul(t *testing.T) {
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
	expected := new(bn256.G1)
	expected.ScalarMult(p, scalar)
	expectedXStr, expectedYStr, _ := extractAndConvert(expected.String())
	//expectedX, _ := new(big.Int).SetString(expectedXStr, 10)
	//expectedY, _ := new(big.Int).SetString(expectedYStr, 10)

	log.Println("expected:", expectedXStr, expectedYStr)

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

	nbLen := 1
	//P := make([]bn254.G1Affine, nbLen)
	//S := make([]fr.Element, nbLen)
	//for i := 0; i < nbLen; i++ {
	//	S[i].SetRandom()
	//	P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	//}

	//g10.ScalarMultiplication(&g10, scalar)
	S := []fr.Element{*new(fr.Element).SetBigInt(scalar)}
	P := []bn254.G1Affine{g10}
	var res bn254.G1Affine
	_, err = res.MultiExp(P, S, ecc.MultiExpConfig{})
	log.Println("G1Affine:", res.X.String(), res.Y.String())

	assert.NoError(err)
	cP := make([]sw_emulated.AffinePoint[emulated.BN254Fp], len(P))
	for i := range cP {
		cP[i] = sw_emulated.AffinePoint[emulated.BN254Fp]{
			X: emulated.ValueOf[emparams.BN254Fp](P[i].X),
			Y: emulated.ValueOf[emparams.BN254Fp](P[i].Y),
		}
	}
	cS := make([]emulated.Element[emparams.BN254Fr], len(S))
	for i := range cS {
		cS[i] = emulated.ValueOf[emparams.BN254Fr](S[i])
	}

	assignment := MultiScalarMul[emparams.BN254Fp, emparams.BN254Fr]{
		Points:  cP,
		Scalars: cS,
		Res: sw_emulated.AffinePoint[emparams.BN254Fp]{
			X: emulated.ValueOf[emparams.BN254Fp](res.X),
			Y: emulated.ValueOf[emparams.BN254Fp](res.Y),
		},
	}
	err = test.IsSolved(&MultiScalarMul[emparams.BN254Fp, emparams.BN254Fr]{
		Points:  make([]sw_emulated.AffinePoint[emparams.BN254Fp], nbLen),
		Scalars: make([]emulated.Element[emparams.BN254Fr], nbLen),
	}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBN254MultiScalarMul(t *testing.T) {
	assert := test.NewAssert(t)
	x, _ := new(big.Int).SetString("13534086339230182803823178260078315691269243572458753455438283544709107378988", 10)
	y, _ := new(big.Int).SetString("9053077977614827188269653632534212501565186534180282672519599630892718179094", 10)
	scalar, _ := new(big.Int).SetString("21018549926786911420919261871844456760738199621624594828144407595472474813958", 10)

	var g10 = bn254.G1Affine{}
	_, err := g10.X.SetString(x.String())
	if err != nil {
		panic(err)
	}
	_, err = g10.Y.SetString(y.String())
	if err != nil {
		panic(err)
	}
	assert.True(g10.IsOnCurve())

	S := []fr.Element{*new(fr.Element).SetBigInt(scalar)}
	P := []bn254.G1Affine{g10}
	var res bn254.G1Affine
	_, err = res.MultiExp(P, S, ecc.MultiExpConfig{})
	log.Println("G1Affine:", res.X.String(), res.Y.String())

	assert.NoError(err)

	assignment := BN254MultiScalarMul{
		Point:  [2]frontend.Variable{x, y},
		Scalar: frontend.Variable(scalar),
		Res:    [2]frontend.Variable{res.X.BigInt(new(big.Int)), res.Y.BigInt(new(big.Int))},
	}
	err = test.IsSolved(&BN254MultiScalarMul{
		Point:  [2]frontend.Variable{},
		Scalar: frontend.Variable(scalar),
		Res:    [2]frontend.Variable{},
	}, &assignment, ecc.BN254.ScalarField())

	assert.NoError(err)
}
