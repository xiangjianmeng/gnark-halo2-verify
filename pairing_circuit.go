package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
)

// BN256PairingCircuit is the circuit that performs a bn256 pairing operation
type BN256PairingCircuit struct {
	// Inputs
	G1Points [2]*sw_bn254.G1Affine
	G2Points [2]*sw_bn254.G2Affine
}

// Define the circuit
func (c *BN256PairingCircuit) Define(api frontend.API) error {
	return VerifyBN256Pairing(
		api,
		c.G1Points[:],
		c.G2Points[:],
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

func (c *BN256PairingCircuit) FillVerifyCircuitsG1(x1, y1, x2, y2 frontend.Variable) {
	var g10 = bn254.G1Affine{}
	_, err1 := g10.X.SetInterface(x1)
	_, err2 := g10.Y.SetInterface(y1)
	if err1 != nil || err2 != nil || !g10.IsOnCurve() {
		panic(fmt.Sprintf("err1 = %v, err2 = %v", err1, err2))
	}

	var g11 = bn254.G1Affine{}
	_, err1 = g11.X.SetInterface(x2)
	_, err2 = g11.Y.SetInterface(y2)
	if err1 != nil || err2 != nil || !g11.IsOnCurve() {
		panic(fmt.Sprintf("err1 = %v, err2 = %v", err1, err2))
	}

	swG10 := sw_bn254.NewG1Affine(g10)
	swG11 := sw_bn254.NewG1Affine(g11)
	c.G1Points = [2]*sw_bn254.G1Affine{&swG10, &swG11}

}

func (c *BN256PairingCircuit) FillVerifyCircuitsG2() {
	g20, g21 := GetVerifyCircuitsG2Jac()

	var g20GenAff, g21GenAff bn254.G2Affine
	g20GenAff.FromJacobian(&g20)
	g21GenAff.FromJacobian(&g21)
	log.Println("GenAff IsOnCurve", g20GenAff.IsOnCurve(), g21GenAff.IsOnCurve())

	swG20 := sw_bn254.NewG2Affine(g20GenAff)
	swG21 := sw_bn254.NewG2Affine(g21GenAff)

	c.G2Points = [2]*sw_bn254.G2Affine{&swG20, &swG21}
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
