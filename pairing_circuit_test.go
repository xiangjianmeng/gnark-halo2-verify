package main

import (
	"log"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func setupKeys() (groth16.ProvingKey, groth16.VerifyingKey, constraint.ConstraintSystem) {
	circuit := BN256PairingCircuit{}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}

	//srs, srsLagrange, err := unsafekzg.NewSRS(r1cs)
	//if err != nil {
	//	log.Fatalf("Failed to setup keys: %v", err)
	//}
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("Failed to setup keys: %v", err)
	}
	return pk, vk, r1cs
}

func createProof(pk groth16.ProvingKey, r1cs constraint.ConstraintSystem) (groth16.Proof, witness.Witness) {
	x1, _ := new(big.Int).SetString("2920616387084030925907755037226454382846345550621956833249622258647667607078", 10)
	y1, _ := new(big.Int).SetString("16502678157049327323910877548707266122319935523346850792311342099791838736912", 10)
	x2, _ := new(big.Int).SetString("7162082828732168937516361335135022403650719329242056518668518043784043198510", 10)
	y2, _ := new(big.Int).SetString("18768486256042060147567165227366772940689098806912976766549486364846889365307", 10)
	witnessCircuit := BN256PairingCircuit{x1, y1, x2, y2}

	witness, err := frontend.NewWitness(&witnessCircuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to create proof: %v", err)
	}

	public, err := witness.Public()
	if err != nil {
		log.Fatalf("Failed to Public: %v", err)
	}

	return proof, public
}

func verifyProof(proof groth16.Proof, vk groth16.VerifyingKey, witness witness.Witness) bool {
	if err := groth16.Verify(proof, vk, witness); err != nil {
		log.Fatalf("Failed to verify proof: %v", err)
		return false
	}
	return true
}

func TestPairingCheckTestSolve(t *testing.T) {
	circuit := BN256PairingCircuit{}

	x1, _ := new(big.Int).SetString("2920616387084030925907755037226454382846345550621956833249622258647667607078", 10)
	y1, _ := new(big.Int).SetString("16502678157049327323910877548707266122319935523346850792311342099791838736912", 10)
	x2, _ := new(big.Int).SetString("7162082828732168937516361335135022403650719329242056518668518043784043198510", 10)
	y2, _ := new(big.Int).SetString("18768486256042060147567165227366772940689098806912976766549486364846889365307", 10)

	witnessCircuit := BN256PairingCircuit{
		x11: frontend.Variable(x1),
		y11: frontend.Variable(y1),
		x12: frontend.Variable(x2),
		y12: frontend.Variable(y2),
	}
	err := test.IsSolved(&circuit, &witnessCircuit, ecc.BN254.ScalarField())

	assert := test.NewAssert(t)
	assert.NoError(err)
}

func TestPairing(t *testing.T) {
	log.Println("setupKeys start !")
	pk, vk, r1cs := setupKeys()
	log.Println("setupKeys end !")

	log.Println("createProof start !")
	proof, public := createProof(pk, r1cs)
	log.Println("createProof end !")

	if verifyProof(proof, vk, public) {
		log.Println("Proof verified successfully!")
	} else {
		log.Println("Failed to verify proof.")
	}

}

func TestOnCurve(t *testing.T) {
	assert := test.NewAssert(t)

	// proof[102]
	var g10 = bn254.G1Jac{}
	_, err := g10.X.SetString("2920616387084030925907755037226454382846345550621956833249622258647667607078")
	if err != nil {
		panic(err)
	}
	_, err = g10.Y.SetString("16502678157049327323910877548707266122319935523346850792311342099791838736912")
	if err != nil {
		panic(err)
	}
	g10.Z.SetOne()
	assert.True(g10.IsOnCurve())
	var g10GAff bn254.G1Affine
	g10GAff.FromJacobian(&g10)
	assert.True(g10GAff.IsOnCurve())

	var g11 = bn254.G1Jac{}
	_, err = g11.X.SetString("7162082828732168937516361335135022403650719329242056518668518043784043198510")
	if err != nil {
		panic(err)
	}
	_, err = g11.Y.SetString("18768486256042060147567165227366772940689098806912976766549486364846889365307")
	if err != nil {
		panic(err)
	}
	g11.Z.SetOne()
	assert.True(g11.IsOnCurve())
	var g11GAff bn254.G1Affine
	g11GAff.FromJacobian(&g11)
	assert.True(g11GAff.IsOnCurve())

	g20, g21 := GetVerifyCircuitsG2Jac()
	assert.True(g20.IsOnCurve())
	assert.True(g21.IsOnCurve())
}
