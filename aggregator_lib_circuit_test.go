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

func TestBigMod(t *testing.T) {
	b, _ := new(big.Int).SetString("7264406879962038625787264009404137460377457101078411404048363683262191883717", 10)
	aux, _ := new(big.Int).SetString("14682075548635262302074385051110702234086274396931195933546742286128764358125", 10)

	q_mod, _ := new(big.Int).SetString(FrModulus, 10)

	product := b.Mul(b, aux)

	log.Println(product.String())

	log.Println(product.Mod(product, q_mod).String())
}

func TestHexToBase(t *testing.T) {
	bufStr := []string{
		"14518669122153204107438001167275775392293121025028421520190945678452919453116",
		"17093993445643899230068359428052269750701581214259397668825355106622530890359",
		"11998403060490390570455295813295651267749063915313021105374173689081403863257",
		"2495735567390302507201888405163469563532488217546814052976483435583288670565",
		"14059003638501981466784405033930231791072560930660624891412078762767896781609",
		"9618638276073043292923148356967627316354531496479286038747655855210260248763",
		"7264406879962038625787264009404137460377457101078411404048363683262191883717",
		"11388297455859133038480661962794609878975270610033719337414430187627923593514",
		"5407378722455163557827638766233330495102514713373201611482560475011947871717",
		"10696824190703641741008737755241846718268731271095825424278589440469985414304",
	}

	buf := make([]*big.Int, len(proofStr))
	for i := 0; i < len(bufStr); i++ {
		buf[i], _ = new(big.Int).SetString(bufStr[i], 10)
		log.Println(buf[i].String())
	}
}

func TestSqueezeChallenge(t *testing.T) {
	//bufStr := []string{
	//	"14518669122153204107438001167275775392293121025028421520190945678452919453116",
	//	"17093993445643899230068359428052269750701581214259397668825355106622530890359",
	//	"11998403060490390570455295813295651267749063915313021105374173689081403863257",
	//	"2495735567390302507201888405163469563532488217546814052976483435583288670565",
	//	"14059003638501981466784405033930231791072560930660624891412078762767896781609",
	//	"9618638276073043292923148356967627316354531496479286038747655855210260248763",
	//	"7264406879962038625787264009404137460377457101078411404048363683262191883717",
	//	"11388297455859133038480661962794609878975270610033719337414430187627923593514",
	//	"5407378722455163557827638766233330495102514713373201611482560475011947871717",
	//	"10696824190703641741008737755241846718268731271095825424278589440469985414304",
	//}

	//bufStr := []string{
	//	"00000000000000000000000000000000000000000000000061f96cb6aff57754",
	//	"000000000000000000000000000000000000000000000000237b2cbd779f0d98",
	//	"2e7813e2ab7095204c7efba4fbe356d60b3064b86c1b1ef234edd4eebcab3606",
	//	"0000000000000000000000000000000000000000000000007c8b5f18e9bf5443",
	//	"1760673487281a87933156f40a53a46969cc882c0ed465f69cc380001ba0e26a",
	//	"0000000000000000000000000000000000000000000000000000000000000000",
	//	"0000000000000000000000000000000000000000000000000000000000000000",
	//	"0000000000000000000000000000000000000000000000000000000000000000",
	//	"0000000000000000000000000000000000000000000000000000000000000000",
	//	"0000000000000000000000000000000000000000000000000000000000000000",
	//}

	bufStr := []string{
		"100f8232cd716f876ec209e5b0e8eab6d5b81abca006ac0c614934d827f3d5c5",
		"1ded2b235ff4e7353a5698f7a0a59ec15372b5523c5be63ca303edc944b1b1cf",
		"1ded2b235ff4e7353a5698f7a0a59ec15372b5523c5be63ca303edc944b1b1ce",
	}

	//buf := make([]*big.Int, len(proofStr))
	//for i := 0; i < len(bufStr); i++ {
	//	buf[i], _ = new(big.Int).SetString(bufStr[i], 16)
	//	log.Println(buf[i].String())
	//}

	var inputBytes []byte
	for i := 0; i < len(bufStr); i++ {
		res, _ := new(big.Int).SetString(bufStr[i], 16)
		log.Println(res.String())
		inputBytes = append(inputBytes, res.FillBytes(make([]byte, 32))...)
	}
	//inputBytes = append(inputBytes, 0x0)
	//ethHashVal := sha256.Sum256(inputBytes)
	//ethHashBig := new(big.Int).SetBytes(ethHashVal[:])
	//log.Println(ethHashBig.Mod(ethHashBig, MODULUS))
}
