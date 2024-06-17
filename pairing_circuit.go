package main

import (
	"fmt"

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
