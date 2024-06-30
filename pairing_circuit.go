package main

import (
	"fmt"
	"github.com/consensys/gnark/std/math/emulated"
	"log"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// BN256PairingCircuit is the circuit that performs a bn256 pairing operation
type BN256PairingCircuit struct {
	// Inputs
	x11, y11, x12, y12 frontend.Variable
}

// Define the circuit
func (c *BN256PairingCircuit) Define(api frontend.API) error {
	G1Points, err := FillVerifyCircuitsG1(api, c.x11, c.y11, c.x12, c.y12)
	if err != nil {
		return err
	}
	G2Points := FillVerifyCircuitsG2()
	return VerifyBN256Pairing(
		api,
		G1Points[:],
		G2Points[:],
	)
}

func VerifyBN256Pairing(
	api frontend.API,
	g1Points []*sw_bn254.G1Affine,
	g2Points []*sw_bn254.G2Affine,
) error {
	pairing, err := sw_bn254.NewPairing(api)
	if err != nil {
		return fmt.Errorf("NewPairing: %w", err)
	}
	// Initialize pairing engine
	err = pairing.PairingCheck(
		g1Points,
		g2Points,
	)
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	return nil
}

func FillVerifyCircuitsG1(api frontend.API, x1, y1, x2, y2 frontend.Variable) ([2]*sw_bn254.G1Affine, error) {
	log.Println("FillVerifyCircuitsG1", x1, y1, x2, y2)
	p1, err := ToPoint[emulated.BN254Fp](api, [2]frontend.Variable{x1, y1})
	if err != nil {
		return [2]*sw_bn254.G1Affine{}, err
	}

	p2, err := ToPoint[emulated.BN254Fp](api, [2]frontend.Variable{x2, y2})
	if err != nil {
		return [2]*sw_bn254.G1Affine{}, err
	}

	return [2]*sw_bn254.G1Affine{&p1, &p2}, nil
}

func FillVerifyCircuitsG2() [2]*sw_bn254.G2Affine {
	g20, g21 := GetVerifyCircuitsG2Jac()

	var g20GenAff, g21GenAff bn254.G2Affine
	g20GenAff.FromJacobian(&g20)
	g21GenAff.FromJacobian(&g21)
	log.Println("GenAff IsOnCurve", g20GenAff.IsOnCurve(), g21GenAff.IsOnCurve())

	swG20 := sw_bn254.NewG2Affine(g20GenAff)
	swG21 := sw_bn254.NewG2Affine(g21GenAff)

	return [2]*sw_bn254.G2Affine{&swG20, &swG21}
}

func GetVerifyCircuitsG2Jac() (bn254.G2Jac, bn254.G2Jac) {
	var g20 = bn254.G2Jac{}
	g20.X.SetString(
		"13560776910958896778309428450808722712362583089620853136731412215646945297830",
		"17006984783035916014836003241042945838018391379603479329912940809520477208052",
	)
	g20.Y.SetString(
		"18091431719069275340788954644764755415339503689597559484185985670418402491565",
		"12900589361605111856143562381318004229723309245412571888359653960504992734777",
	)
	g20.Z.SetString("1", "0")
	if !g20.IsOnCurve() {
		panic("is not on Curve")
	}

	var g21 = bn254.G2Jac{}
	g21.X.SetString(
		"10857046999023057135944570762232829481370756359578518086990519993285655852781",
		"11559732032986387107991004021392285783925812861821192530917403151452391805634",
	)
	g21.Y.SetString(
		"13392588948715843804641432497768002650278120570034223513918757245338268106653",
		"17805874995975841540914202342111839520379459829704422454583296818431106115052",
	)
	g21.Z.SetString("1", "0")
	if !g21.IsOnCurve() {
		panic("is not on Curve")
	}

	return g20, g21
}
