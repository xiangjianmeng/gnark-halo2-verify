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
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/ethereum/go-ethereum/crypto/bn256"
)

var (
	FpModulus          = "21888242871839275222246405745257275088696311157297823662689037894645226208583"
	FrModulus          = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
	MODULUS   *big.Int = emulated.BN254Fr{}.Modulus()
)

func init() {
	solver.RegisterHint(MsmHint)
	solver.RegisterHint(AddHint)
	solver.RegisterHint(Keccak256Hint)
}

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
	//log.Println("VerifyBN256Msm", g1Point.String(), res.String())
	api.AssertIsEqual(g1Point.X, res.X)
	api.AssertIsEqual(g1Point.Y, res.Y)
	return nil
}

// BN256AddCircuit is the circuit that performs a bn256 pairing operation
type BN256AddCircuit struct {
	// Inputs
	G10Point *bn254.G1Affine
	G11Point *bn254.G1Affine
	Res      *bn254.G1Affine
}

func (c *BN256AddCircuit) Define(api frontend.API) error {
	return VerifyBN256Add(
		api,
		c.G10Point,
		c.G11Point,
		c.Res,
	)
}

func VerifyBN256Add(
	api frontend.API,
	g10Point *bn254.G1Affine,
	g11Point *bn254.G1Affine,
	res *bn254.G1Affine,
) error {
	sum := g10Point.Add(g10Point, g11Point)
	api.AssertIsEqual(sum.X, res.X)
	api.AssertIsEqual(sum.Y, res.Y)
	return nil
}

func CalcVerifyCircuitLagrange(api frontend.API, buf []frontend.Variable) error {
	x, _ := new(big.Int).SetString("13534086339230182803823178260078315691269243572458753455438283544709107378988", 10)
	y, _ := new(big.Int).SetString("9053077977614827188269653632534212501565186534180282672519599630892718179094", 10)

	res, err := CalcVerifyBN256Msm(api, x, y, buf[2])
	buf[0] = res[0]
	buf[1] = res[1]
	return err
}

func MsmHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 3 {
		panic("MulAddHint expects 3 input operands")
	}
	var blob []byte
	bufByte0 := inputs[0].FillBytes(make([]byte, 32))
	blob = append(blob, bufByte0[:]...)
	bufByte1 := inputs[1].FillBytes(make([]byte, 32))
	blob = append(blob, bufByte1[:]...)
	p := new(bn256.G1)
	_, err := p.Unmarshal(blob)
	if err != nil {
		return err
	}
	res := new(bn256.G1)
	res.ScalarMult(p, inputs[2])

	xStr, yStr, _ := extractAndConvert(res.String())
	results[0], _ = new(big.Int).SetString(xStr, 10)
	results[1], _ = new(big.Int).SetString(yStr, 10)
	return nil
}

func CalcVerifyBN256Msm1(api frontend.API, x, y, k frontend.Variable) ([2]frontend.Variable, error) {
	result, err := api.Compiler().NewHint(MsmHint, 2, x, y, k)
	if err != nil {
		panic(err)
	}

	var g10 = bn254.G1Affine{}
	_, err = g10.X.SetInterface(x)
	if err != nil {
		panic(err)
	}
	_, err = g10.Y.SetInterface(y)
	if err != nil {
		panic(err)
	}
	if !g10.IsOnCurve() {
		return [2]frontend.Variable{}, errors.New("bn256.G1Affine is not on curve")
	}

	var resCircuit = bn254.G1Affine{}
	_, err = resCircuit.X.SetInterface(result[0])
	if err != nil {
		panic(err)
	}
	_, err = resCircuit.Y.SetInterface(result[1])
	if err != nil {
		panic(err)
	}
	//return [2]frontend.Variable{result[0], result[1]}, VerifyBN256Msm(api, &g10, k.(*big.Int), &resCircuit)
	return [2]frontend.Variable{resCircuit.X.BigInt(new(big.Int)), resCircuit.Y.BigInt(new(big.Int))}, VerifyBN256Msm(api, &g10, k.(*big.Int), &resCircuit)
}

func CalcVerifyBN256Msm(api frontend.API, x, y, k frontend.Variable) ([2]frontend.Variable, error) {
	result, err := api.Compiler().NewHint(MsmHint, 2, x, y, k)
	if err != nil {
		panic(err)
	}
	//var resCircuit = bn254.G1Affine{}
	//_, err = resCircuit.X.SetInterface(result[0])
	//if err != nil {
	//	panic(err)
	//}
	//_, err = resCircuit.Y.SetInterface(result[1])
	//if err != nil {
	//	panic(err)
	//}
	//return [2]frontend.Variable{result[0], result[1]}, VerifyBN256Msm(api, &g10, k.(*big.Int), &resCircuit)
	expectedX, expectedY := mod(api, result[0]), mod(api, result[1])
	err = VerifyBN254ScalarMul(api, [2]frontend.Variable{x, y}, k, [2]frontend.Variable{expectedX, expectedY})
	return [2]frontend.Variable{expectedX, expectedY}, err
}

func AddHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 4 {
		panic("MulAddHint expects 3 input operands")
	}

	var blob1 []byte
	bufByte0 := inputs[0].FillBytes(make([]byte, 32))
	blob1 = append(blob1, bufByte0[:]...)
	bufByte1 := inputs[1].FillBytes(make([]byte, 32))
	blob1 = append(blob1, bufByte1[:]...)
	p1 := new(bn256.G1)
	_, err := p1.Unmarshal(blob1)
	if err != nil {
		return err
	}

	var blob2 []byte
	bufByte2 := inputs[2].FillBytes(make([]byte, 32))
	blob2 = append(blob2, bufByte2[:]...)
	bufByte3 := inputs[3].FillBytes(make([]byte, 32))
	blob2 = append(blob2, bufByte3[:]...)
	p2 := new(bn256.G1)
	_, err = p2.Unmarshal(blob2)
	if err != nil {
		return err
	}

	res := new(bn256.G1)
	res = res.Add(p1, p2)

	xStr, yStr, _ := extractAndConvert(res.String())
	results[0], _ = new(big.Int).SetString(xStr, 10)
	results[1], _ = new(big.Int).SetString(yStr, 10)
	return nil
}

func CalcVerifyBN256Add1(api frontend.API, x1, y1, x2, y2 frontend.Variable) ([2]frontend.Variable, error) {
	result, err := api.Compiler().NewHint(AddHint, 2, x1, y1, x2, y2)
	// TODO: sanity check

	// circuit
	var g10 = bn254.G1Affine{}
	_, err = g10.X.SetInterface(x1)
	if err != nil {
		panic(err)
	}
	_, err = g10.Y.SetInterface(y1)
	if err != nil {
		panic(err)
	}
	if !g10.IsOnCurve() {
		return [2]frontend.Variable{}, errors.New("bn256.G1Affine is not on curve")
	}

	var g11 = bn254.G1Affine{}
	_, err = g11.X.SetInterface(x2)
	if err != nil {
		panic(err)
	}
	_, err = g11.Y.SetInterface(y2)
	if err != nil {
		panic(err)
	}
	if !g11.IsOnCurve() {
		return [2]frontend.Variable{}, errors.New("bn256.G1Affine is not on curve")
	}

	var resCircuit = bn254.G1Affine{}
	_, err = resCircuit.X.SetInterface(result[0])
	if err != nil {
		panic(err)
	}
	_, err = resCircuit.Y.SetInterface(result[1])
	if err != nil {
		panic(err)
	}

	return [2]frontend.Variable{resCircuit.X.BigInt(new(big.Int)), resCircuit.Y.BigInt(new(big.Int))}, VerifyBN256Add(api, &g10, &g11, &resCircuit)
}

func CalcVerifyBN256Add(api frontend.API, x1, y1, x2, y2 frontend.Variable) ([2]frontend.Variable, error) {
	result, err := api.Compiler().NewHint(AddHint, 2, x1, y1, x2, y2)
	expectedX, expectedY := mod(api, result[0]), mod(api, result[1])
	err = VerifyBN254Add(api, [2]frontend.Variable{x1, y1}, [2]frontend.Variable{x2, y2}, [2]frontend.Variable{expectedX, expectedY})
	return [2]frontend.Variable{expectedX, expectedY}, err
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
	//var xFr, yFr fr.Element
	xFr, _ := new(fp.Element).SetInterface(x)
	yFr, _ := new(fp.Element).SetInterface(y)
	g1.X.Set(xFr)
	g1.Y.Set(yFr)

	// Enforce y² = x³ + 3
	if !g1.IsOnCurve() {
		return errors.New("bn256.G1Affine is not on curve")
	}
	return nil
}

type CheckOnCurveCircuitVar struct {
	X frontend.Variable
	Y frontend.Variable
}

func (circuit CheckOnCurveCircuitVar) Define(api frontend.API) error {
	return VerifyCheckOnCurveVar(api, circuit.X, circuit.Y)
}

func VerifyCheckOnCurveVar(
	api frontend.API,
	x frontend.Variable,
	y frontend.Variable,
) error {
	var g1 = bn254.G1Affine{}
	g1.X.SetInterface(x)
	g1.Y.SetInterface(y)

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
	absorbing[length] = new(big.Int).SetUint64(0)

	var inputBytes []byte
	for i := 0; i < length; i++ {
		//log.Println("absorbing", absorbing[i].(*big.Int).String())
		res := absorbing[i].(*big.Int).FillBytes(make([]byte, 32))
		inputBytes = append(inputBytes, res[:]...)
	}
	inputBytes = append(inputBytes, 0x0)
	ethHashVal := sha256.Sum256(inputBytes)

	inputCircuit := uints.NewU8Array(inputBytes)
	hashValCircuit := uints.NewU8Array(ethHashVal[:])
	err := VerifySha256(api, inputCircuit, hashValCircuit)
	if err != nil {
		return nil, err
	}
	ethHashBig := new(big.Int).SetBytes(ethHashVal[:])
	absorbing[0] = ethHashBig
	//log.Println("ethHashBig", ethHashBig.String())
	return new(big.Int).Mod(ethHashBig, qMod), nil
}

func GetChallengesShPlonkCircuit(
	api frontend.API,
	buf []frontend.Variable, // buf[0..1] is instance_commitment
	transcript []frontend.Variable,
) error {
	var absorbing = make([]frontend.Variable, 112)
	absorb0, _ := new(big.Int).SetString("8025805240938309707562879759498205008153592202559235423490485577859843831056", 10)
	absorbing[0] = absorb0

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

func VerifyNotZero(api frontend.API, x frontend.Variable) error {
	//notZero, err := api.Compiler().NewHint(isNonZero, 1, x)
	//if err != nil {
	//	return err
	//}
	api.AssertIsLessOrEqual(1, x)
	//api.AssertIsEqual(api.Mul(x, notZero[0]), x)
	return nil
}

type RangeCheckCircuit struct {
	X   frontend.Variable `gnark:",public"` // 待检查的变量
	Min frontend.Variable
	Max frontend.Variable
}

func VerifyRangeCheck(api frontend.API, x frontend.Variable, Min frontend.Variable, Max frontend.Variable) error {
	api.AssertIsLessOrEqual(Min, x)
	api.AssertIsLessOrEqual(x, Max)
	return nil
}
