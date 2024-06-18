package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/ethereum/go-ethereum/crypto/bn256"
)

var (
	FpModulus = "21888242871839275222246405745257275088696311157297823662689037894645226208583"
	FrModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
)

// BN256MsmCircuit is the circuit that performs a bn256 pairing operation
type BN256MsmCircuit struct {
	// Inputs
	G1Point *bn254.G1Affine
	Scalar  *big.Int
	Res     *bn254.G1Affine
}

func (c *BN256MsmCircuit) Define(api frontend.API) error {
	return VerifyBN256Msm(
		api,
		c.G1Point,
		c.Scalar,
		c.Res,
	)
}

func VerifyBN256Msm(
	api frontend.API,
	g1Point *bn254.G1Affine,
	scalar *big.Int,
	res *bn254.G1Affine,
) error {
	g1Point = g1Point.ScalarMultiplication(g1Point, scalar)
	api.AssertIsEqual(g1Point.X, res.X)
	api.AssertIsEqual(g1Point.Y, res.Y)
	return nil
}

func calcVerifyCircuitLagrange(api frontend.API, buf []frontend.Variable) error {
	x, _ := new(big.Int).SetString("13534086339230182803823178260078315691269243572458753455438283544709107378988", 10)
	y, _ := new(big.Int).SetString("9053077977614827188269653632534212501565186534180282672519599630892718179094", 10)

	var blob []byte
	blob = append(blob, x.FillBytes(make([]byte, 32))...)
	blob = append(blob, y.FillBytes(make([]byte, 32))...)

	p := new(bn256.G1)
	_, err := p.Unmarshal(blob)
	if err != nil {
		return err
	}
	res := new(bn256.G1)
	scalar := new(big.Int).Set(buf[2].(*big.Int))
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
	if !g10.IsOnCurve() {
		return errors.New("bn256.G1Affine is not on curve")
	}

	var resCircuit = bn254.G1Affine{}
	xStr, yStr, _ := extractAndConvert(res.String())
	_, err = resCircuit.X.SetString(xStr)
	if err != nil {
		panic(err)
	}
	_, err = resCircuit.Y.SetString(yStr)
	if err != nil {
		panic(err)
	}
	return VerifyBN256Msm(api, &g10, scalar, &resCircuit)
}

func extractAndConvert(input string) (string, string, error) {
	re := regexp.MustCompile(`bn256\.G1\((\w+),\s(\w+)\)`)

	matches := re.FindStringSubmatch(input)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid input format")
	}

	xStr := matches[1]
	yStr := matches[2]

	x10Str, err := hexToDecimalString(xStr)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode x: %v", err)
	}

	y10Str, err := hexToDecimalString(yStr)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode y: %v", err)
	}

	return x10Str, y10Str, nil
}

// Converts hex string to decimal string
func hexToDecimalString(hexStr string) (string, error) {
	// Strip leading "0x" if it exists
	hexStr = strings.TrimPrefix(hexStr, "0x")

	// Convert hex to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	// Convert bytes to big.Int
	bigInt := new(big.Int).SetBytes(bytes)

	// Convert big.Int to decimal string
	return bigInt.String(), nil
}

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

type CheckOnCurveCircuit struct {
	X frontend.Variable
	Y frontend.Variable
}

func (circuit CheckOnCurveCircuit) Define(api frontend.API) error {
	return VerifyCheckOnCurve(api, circuit.X, circuit.Y)
}

func VerifyCheckOnCurve(
	api frontend.API,
	x frontend.Variable,
	y frontend.Variable,
) error {
	var g1 = bn254.G1Affine{}
	g1.X.SetBigInt(x.(*big.Int))
	g1.Y.SetBigInt(y.(*big.Int))

	// Enforce y² = x³ + 3
	if !g1.IsOnCurve() {
		return errors.New("bn256.G1Affine is not on curve")
	}
	return nil
}

func SqueezeChallenge(
	api frontend.API,
	absorbing []frontend.Variable,
	length int,
) (frontend.Variable, error) {
	// TODO: uint256 len = length * 32 + 1;
	qMod, _ := new(big.Int).SetString(FrModulus, 10)
	absorbing[length] = frontend.Variable(new(big.Int).SetUint64(0))
	var inputBytes []byte
	for i := 0; i < length; i++ {
		inputBytes = append(inputBytes, absorbing[i].(*big.Int).FillBytes(make([]byte, 32))...)
	}
	ethHashVal := sha256.Sum256(inputBytes)

	inputCircuit := uints.NewU8Array(inputBytes)
	hashValCircuit := uints.NewU8Array(ethHashVal[:])
	err := VerifySha256(api, inputCircuit, hashValCircuit)
	if err != nil {
		return nil, err
	}
	ethHashBig := new(big.Int).SetBytes(ethHashVal[:])
	absorbing[0] = frontend.Variable(ethHashBig)
	return frontend.Variable(ethHashBig.Mod(ethHashBig, qMod)), nil
}

func GetChallengesShPlonkCircuit(
	api frontend.API,
	buf []frontend.Variable, // buf[0..1] is instance_commitment
	transcript []frontend.Variable,
) error {
	var absorbing = make([]frontend.Variable, 112)
	absorb0, _ := new(big.Int).SetString("17724118764413096111953866478519597650467920633612431492898416022004649110250", 10)
	absorbing[0] = frontend.Variable(absorb0)

	absorbing[1] = buf[0]
	absorbing[2] = buf[1]

	pos := 3
	transcriptPos := 0
	for i := 0; i < 8; i++ {
		err := VerifyCheckOnCurve(api, transcript[transcriptPos], transcript[transcriptPos+1])
		if err != nil {
			return err
		}
		absorbing[pos] = transcript[transcriptPos]
		pos++
		transcriptPos++
		absorbing[pos] = transcript[transcriptPos]
		pos++
		transcriptPos++
	}

	// theta
	var err error = nil
	buf[2], err = SqueezeChallenge(api, absorbing, pos)
	if err != nil {
		return err
	}

	pos = 1
	for i := 0; i < 4; i++ {
		err := VerifyCheckOnCurve(api, transcript[transcriptPos], transcript[transcriptPos+1])
		if err != nil {
			return err
		}
		absorbing[pos] = transcript[transcriptPos]
		pos++
		transcriptPos++
		absorbing[pos] = transcript[transcriptPos]
		pos++
		transcriptPos++
	}
	// beta
	buf[3], err = SqueezeChallenge(api, absorbing, pos)
	if err != nil {
		return err
	}

	pos = 1
	// gamma
	buf[4], err = SqueezeChallenge(api, absorbing, pos)
	if err != nil {
		return err
	}

	pos = 1
	for i := 0; i < 7; i++ {
		err := VerifyCheckOnCurve(api, transcript[transcriptPos], transcript[transcriptPos+1])
		if err != nil {
			return err
		}
		absorbing[pos] = transcript[transcriptPos]
		pos++
		transcriptPos++
		absorbing[pos] = transcript[transcriptPos]
		pos++
		transcriptPos++
	}
	// y
	buf[5], err = SqueezeChallenge(api, absorbing, pos)
	if err != nil {
		return err
	}

	pos = 1
	for i := 0; i < 3; i++ {
		err := VerifyCheckOnCurve(api, transcript[transcriptPos], transcript[transcriptPos+1])
		if err != nil {
			return err
		}
		absorbing[pos] = transcript[transcriptPos]
		pos++
		transcriptPos++
		absorbing[pos] = transcript[transcriptPos]
		pos++
		transcriptPos++
	}
	//x
	buf[6], err = SqueezeChallenge(api, absorbing, pos)
	if err != nil {
		return err
	}

	pos = 1
	for i := 0; i < 56; i++ {
		absorbing[pos] = transcript[transcriptPos]
		pos++
		transcriptPos++
	}
	//y
	buf[7], err = SqueezeChallenge(api, absorbing, pos)
	if err != nil {
		return err
	}

	pos = 1
	//v
	buf[8], err = SqueezeChallenge(api, absorbing, pos)
	if err != nil {
		return err
	}

	err = VerifyCheckOnCurve(api, transcript[transcriptPos], transcript[transcriptPos+1])
	if err != nil {
		return err
	}
	absorbing[pos] = transcript[transcriptPos]
	pos++
	transcriptPos++
	absorbing[pos] = transcript[transcriptPos]
	pos++
	transcriptPos++

	//u
	buf[9], err = SqueezeChallenge(api, absorbing, pos)
	if err != nil {
		return err
	}

	err = VerifyCheckOnCurve(api, transcript[transcriptPos], transcript[transcriptPos+1])
	if err != nil {
		return err
	}

	return nil
}
