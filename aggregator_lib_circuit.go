package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
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

func CalcVerifyBN256Msm(api frontend.API, x, y, k frontend.Variable) ([2]frontend.Variable, error) {
	result, err := api.Compiler().NewHint(MsmHint, 2, x, y, k)
	if err != nil {
		panic(err)
	}
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
	cr, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetCurveParams[emparams.BN254Fp]())
	if err != nil {
		return err
	}

	point, err := ToPoint[emulated.BN254Fp](api, [2]frontend.Variable{x, y})
	if err != nil {
		return err
	}
	cr.AssertIsOnCurve(&point)
	return nil
}

func Sha256Hint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	var inputBytes []byte
	inputBytes = append(inputBytes, inputs[0].FillBytes(make([]byte, 16))[0:16]...)
	inputBytes = append(inputBytes, inputs[1].FillBytes(make([]byte, 16))[0:16]...)
	for i := 2; i < len(inputs); i++ {
		//log.Println("absorbing", absorbing[i].(*big.Int).String())
		res := inputs[i].FillBytes(make([]byte, 32))
		inputBytes = append(inputBytes, res[:]...)
	}
	inputBytes = append(inputBytes, 0x0)
	ethHashVal := sha256.Sum256(inputBytes)

	results[0] = new(big.Int).SetBytes(ethHashVal[0:16])
	results[1] = new(big.Int).SetBytes(ethHashVal[16:])

	//log.Println("inputBytes", ethHashVal)

	i := 2
	for _, bigByte := range ethHashVal {
		results[i] = new(big.Int).SetBytes([]byte{bigByte})
		i++
	}

	for _, bigByte := range inputBytes {
		results[i] = new(big.Int).SetBytes([]byte{bigByte})
		i++
	}
	return nil
}

func GetChallengesShPlonkCircuit(
	api frontend.API,
	buf []frontend.Variable, // buf[0..1] is instance_commitment
	transcript []frontend.Variable,
) error {
	var absorbing = make([]frontend.Variable, 112)
	constNum, _ := new(big.Int).SetString("8025805240938309707562879759498205008153592202559235423490485577859843831056", 10)
	constBytes := constNum.FillBytes(make([]byte, 32))

	absorbing[0] = new(big.Int).SetBytes(constBytes[0:16])
	absorbing[1] = new(big.Int).SetBytes(constBytes[16:])

	absorbing[2] = buf[0]
	absorbing[3] = buf[1]

	pos := 4
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

	pos = 2
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

	pos = 2
	// gamma
	buf[4], err = SqueezeChallenge(api, absorbing, pos)
	if err != nil {
		return err
	}

	pos = 2
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

	pos = 2
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

	pos = 2
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

	pos = 2
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

func SqueezeChallenge(
	api frontend.API,
	absorbing []frontend.Variable,
	length int,
) (frontend.Variable, error) {
	// TODO: uint256 len = length * 32 + 1;
	// +1 append 0x0 in inputBytes, +2 for ethHashVal[0:16], ethHashVal[16:]
	// because use ecc.BN254.ScalarField() when compile, ethHashVal[0:32] exceed ScalarField
	// need to split to ethHashVal[0:16], ethHashVal[16:] to store into absorbing[0] absorbing[1]
	resLen := 32*(length) + 1 + 2
	absorbing[length] = new(big.Int).SetUint64(0)
	//log.Println("absorbing[0] start", absorbing[0])
	result, err := api.Compiler().NewHint(Sha256Hint, resLen, absorbing[0:length]...)
	if err != nil {
		return nil, err
	}

	binaryF, err := uints.New[uints.U32](api)
	if err != nil {
		return nil, err
	}
	var hashU8Array, inputU8Array []uints.U8
	for i := 2; i < 34; i++ {
		hashU8Array = append(hashU8Array, binaryF.ByteValueOf(result[i]))
	}
	for i := 34; i < resLen; i++ {
		inputU8Array = append(inputU8Array, binaryF.ByteValueOf(result[i]))
	}
	err = VerifySha256(api, inputU8Array, hashU8Array)
	if err != nil {
		return nil, err
	}

	ethHashFr := PackUInt8Variables(api, result[2:34]...)
	absorbing[0] = result[0]
	absorbing[1] = result[1]
	api.AssertIsEqual(PackUInt128Variables(api, absorbing[0:2]...), ethHashFr)
	return ethHashFr, err
}
