package main

import (
	"log"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/ethereum/go-ethereum/crypto/bn256"
)

type MultiScalarMul[T, S emulated.FieldParams] struct {
	Points  []sw_emulated.AffinePoint[T]
	Scalars []emulated.Element[S]
	Res     sw_emulated.AffinePoint[T]
}

func (c *MultiScalarMul[T, S]) Define(api frontend.API) error {
	return VerifyMultiScalarMul(api, c.Points, c.Scalars, c.Res)
}

func VerifyMultiScalarMul[T, S emulated.FieldParams](api frontend.API, points []sw_emulated.AffinePoint[T], scalars []emulated.Element[S], expected sw_emulated.AffinePoint[T]) error {
	cr, err := sw_emulated.New[T, S](api, sw_emulated.GetCurveParams[T]())
	if err != nil {
		return err
	}
	ps := make([]*sw_emulated.AffinePoint[T], len(points))
	for i := range points {
		ps[i] = &points[i]
	}
	ss := make([]*emulated.Element[S], len(scalars))
	for i := range scalars {
		ss[i] = &scalars[i]
	}
	res, err := cr.MultiScalarMul(ps, ss)
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &expected)
	return nil
}

func MsmHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 3 {
		panic("MulAddHint expects 3 input operands")
	}
	log.Println("MsmHint", inputs[0], inputs[1], inputs[2])
	if inputs[0].Cmp(big.NewInt(1)) == 0 {
		inputs[1], _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208581", 10)
		log.Println("MsmHint inputs[2]", inputs[2].String())
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
	log.Println("MsmHint", results[0].String(), results[1].String())
	return nil
}

func CalcVerifyBN254Msm(api frontend.API, x, y, k frontend.Variable) ([2]frontend.Variable, error) {
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

func CalcVerifyBN254Add(api frontend.API, x1, y1, x2, y2 frontend.Variable) ([2]frontend.Variable, error) {
	result, err := api.Compiler().NewHint(AddHint, 2, x1, y1, x2, y2)
	expectedX, expectedY := mod(api, result[0]), mod(api, result[1])
	err = VerifyBN254Add(api, [2]frontend.Variable{x1, y1}, [2]frontend.Variable{x2, y2}, [2]frontend.Variable{expectedX, expectedY})
	return [2]frontend.Variable{expectedX, expectedY}, err
}

type BN254ScalarMul struct {
	Point  [2]frontend.Variable
	Scalar frontend.Variable
	Res    [2]frontend.Variable
}

func (c *BN254ScalarMul) Define(api frontend.API) error {
	//var buf = []frontend.Variable{c.Point[0], c.Point[1], c.Scalar}
	//return CalcVerifyCircuitLagrange(api, buf)
	return VerifyBN254ScalarMul(api, c.Point, c.Scalar, c.Res)
}

func VerifyBN254ScalarMul(
	api frontend.API, point [2]frontend.Variable, scalar frontend.Variable, expected [2]frontend.Variable,
) error {
	cr, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetCurveParams[emparams.BN254Fp]())
	if err != nil {
		return err
	}

	ps, err := ToPoint[emulated.BN254Fp](api, point)
	if err != nil {
		return err
	}

	scalarEle, err := ToElement[emulated.BN254Fr](api, scalar)
	if err != nil {
		return err
	}
	res := cr.ScalarMul(&ps, &scalarEle)

	expectedRes, err := ToPoint[emulated.BN254Fp](api, expected)
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &expectedRes)
	return nil
}

type BN254Add struct {
	Point1      [2]frontend.Variable
	Point2      [2]frontend.Variable
	ExpectedRes [2]frontend.Variable
}

func (c *BN254Add) Define(api frontend.API) error {
	return VerifyBN254Add(api, c.Point1, c.Point2, c.ExpectedRes)
}

func VerifyBN254Add(
	api frontend.API, point1 [2]frontend.Variable, point2 [2]frontend.Variable, expected [2]frontend.Variable,
) error {
	cr, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetCurveParams[emparams.BN254Fp]())
	if err != nil {
		return err
	}

	ps1, err := ToPoint[emulated.BN254Fp](api, point1)
	if err != nil {
		return err
	}

	ps2, err := ToPoint[emulated.BN254Fp](api, point2)
	if err != nil {
		return err
	}

	res := cr.Add(&ps1, &ps2)

	expectedRes, err := ToPoint[emulated.BN254Fp](api, expected)
	if err != nil {
		return err
	}
	//log.Println(res)
	//log.Println(&expectedRes)
	cr.AssertIsEqual(res, &expectedRes)
	return nil
}
