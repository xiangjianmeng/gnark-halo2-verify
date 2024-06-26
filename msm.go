package main

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
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

type BN254ScalarMul struct {
	Point  [2]frontend.Variable
	Scalar frontend.Variable
	Res    [2]frontend.Variable
}

func (c *BN254ScalarMul) Define(api frontend.API) error {
	return VerifyBN254ScalarMul(api, c.Point, c.Scalar, c.Res)
}

func VerifyBN254ScalarMul(
	api frontend.API, point [2]frontend.Variable, scalar frontend.Variable, expected [2]frontend.Variable,
) error {
	cr, err := sw_emulated.New[emparams.BN254Fp, emparams.BN254Fr](api, sw_emulated.GetCurveParams[emparams.BN254Fp]())
	if err != nil {
		return err
	}
	x, err := new(fp.Element).SetInterface(point[0])
	if err != nil {
		return err
	}
	y, err := new(fp.Element).SetInterface(point[1])
	if err != nil {
		return err
	}
	ps := &sw_emulated.AffinePoint[emulated.BN254Fp]{
		X: emulated.ValueOf[emparams.BN254Fp](x),
		Y: emulated.ValueOf[emparams.BN254Fp](y),
	}
	scalarEle, err := new(fp.Element).SetInterface(scalar)
	if err != nil {
		return err
	}

	s := emulated.ValueOf[emparams.BN254Fr](*scalarEle)
	res := cr.ScalarMul(ps, &s)

	expectedX, err := new(fp.Element).SetInterface(expected[0])
	if err != nil {
		return err
	}
	expectedY, err := new(fp.Element).SetInterface(expected[1])
	if err != nil {
		return err
	}
	expectedRes := sw_emulated.AffinePoint[emparams.BN254Fp]{
		X: emulated.ValueOf[emparams.BN254Fp](expectedX),
		Y: emulated.ValueOf[emparams.BN254Fp](expectedY),
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

	x1, err := new(fp.Element).SetInterface(point1[0])
	if err != nil {
		return err
	}
	y1, err := new(fp.Element).SetInterface(point1[1])
	if err != nil {
		return err
	}
	ps1 := &sw_emulated.AffinePoint[emulated.BN254Fp]{
		X: emulated.ValueOf[emparams.BN254Fp](x1),
		Y: emulated.ValueOf[emparams.BN254Fp](y1),
	}

	x2, err := new(fp.Element).SetInterface(point2[0])
	if err != nil {
		return err
	}
	y2, err := new(fp.Element).SetInterface(point2[1])
	if err != nil {
		return err
	}
	ps2 := &sw_emulated.AffinePoint[emulated.BN254Fp]{
		X: emulated.ValueOf[emparams.BN254Fp](x2),
		Y: emulated.ValueOf[emparams.BN254Fp](y2),
	}

	res := cr.AddUnified(ps1, ps2)

	expectedX, err := new(fp.Element).SetInterface(expected[0])
	if err != nil {
		return err
	}
	expectedY, err := new(fp.Element).SetInterface(expected[1])
	if err != nil {
		return err
	}
	expectedRes := sw_emulated.AffinePoint[emparams.BN254Fp]{
		X: emulated.ValueOf[emparams.BN254Fp](expectedX),
		Y: emulated.ValueOf[emparams.BN254Fp](expectedY),
	}
	//log.Println(res)
	//log.Println(&expectedRes)
	cr.AssertIsEqual(res, &expectedRes)
	return nil
}
