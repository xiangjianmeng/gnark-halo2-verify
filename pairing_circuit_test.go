package main

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/test"
)

func setupKeys() (groth16.ProvingKey, groth16.VerifyingKey, constraint.ConstraintSystem) {
	circuit := BN256PairingCircuit{
		G1Points: [2]*sw_bn254.G1Affine{new(sw_bn254.G1Affine), new(sw_bn254.G1Affine)},
		G2Points: [2]*sw_bn254.G2Affine{new(sw_bn254.G2Affine), new(sw_bn254.G2Affine)},
	}

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
	witnessCircuit := BN256PairingCircuit{}

	// Set the G1 and G2 points
	var g10 = bn254.G1Affine{}
	_, err := g10.X.SetString("2920616387084030925907755037226454382846345550621956833249622258647667607078")
	if err != nil {
		panic(err)
	}
	_, err = g10.Y.SetString("16502678157049327323910877548707266122319935523346850792311342099791838736912")
	if err != nil {
		panic(err)
	}
	log.Println("g10GAff.IsOnCurve", g10.IsOnCurve())

	var g11 = bn254.G1Affine{}
	_, err = g11.X.SetString("7162082828732168937516361335135022403650719329242056518668518043784043198510")
	if err != nil {
		panic(err)
	}
	_, err = g11.Y.SetString("18768486256042060147567165227366772940689098806912976766549486364846889365307")
	if err != nil {
		panic(err)
	}
	log.Println("g11GAff.IsOnCurve", g11.IsOnCurve())

	swG10 := sw_bn254.NewG1Affine(g10)
	swG11 := sw_bn254.NewG1Affine(g11)
	witnessCircuit.G1Points = [2]*sw_bn254.G1Affine{&swG10, &swG11}

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
	log.Println("g20.IsOnCurve", g20.IsOnCurve())

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
	log.Println("g21.IsOnCurve", g21.IsOnCurve())

	var g20GenAff, g21GenAff bn254.G2Affine
	g20GenAff.FromJacobian(&g20)
	g21GenAff.FromJacobian(&g21)
	log.Println("GenAff IsOnCurve", g20GenAff.IsOnCurve(), g21GenAff.IsOnCurve())

	swG20 := sw_bn254.NewG2Affine(g20GenAff)
	swG21 := sw_bn254.NewG2Affine(g21GenAff)

	witnessCircuit.G2Points = [2]*sw_bn254.G2Affine{&swG20, &swG21}

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
	witnessCircuit := BN256PairingCircuit{}
	circuit := BN256PairingCircuit{
		G1Points: [2]*sw_bn254.G1Affine{new(sw_bn254.G1Affine), new(sw_bn254.G1Affine)},
		G2Points: [2]*sw_bn254.G2Affine{new(sw_bn254.G2Affine), new(sw_bn254.G2Affine)},
	}

	assert := test.NewAssert(t)
	var g10 = bn254.G1Affine{}
	_, err := g10.X.SetString("2920616387084030925907755037226454382846345550621956833249622258647667607078")
	if err != nil {
		panic(err)
	}
	_, err = g10.Y.SetString("16502678157049327323910877548707266122319935523346850792311342099791838736912")
	if err != nil {
		panic(err)
	}
	//g10.Z.SetOne()
	//var g10GAff bn254.G1Affine
	//g10GAff.FromJacobian(&g10)
	log.Println("g10GAff.IsOnCurve", g10.IsOnCurve())

	var g11 = bn254.G1Affine{}
	_, err = g11.X.SetString("7162082828732168937516361335135022403650719329242056518668518043784043198510")
	if err != nil {
		panic(err)
	}
	_, err = g11.Y.SetString("18768486256042060147567165227366772940689098806912976766549486364846889365307")
	if err != nil {
		panic(err)
	}
	//g11.Z.SetOne()
	//var g11GAff bn254.G1Affine
	//g11GAff.FromJacobian(&g11)
	log.Println("g11GAff.IsOnCurve", g11.IsOnCurve())

	log.Println("GenAff IsOnCurve", g10.IsOnCurve(), g11.IsOnCurve())
	swG10 := sw_bn254.NewG1Affine(g10)
	//g11GAff.Neg(&g10GAff)
	swG11 := sw_bn254.NewG1Affine(g11)
	witnessCircuit.G1Points = [2]*sw_bn254.G1Affine{&swG10, &swG11}

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
	log.Println("g20.IsOnCurve", g20.IsOnCurve())

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
	log.Println("g21.IsOnCurve", g21.IsOnCurve())

	var g20GenAff, g21GenAff bn254.G2Affine
	g20GenAff.FromJacobian(&g20)
	g21GenAff.FromJacobian(&g21)
	log.Println("GenAff IsOnCurve", g20GenAff.IsOnCurve(), g21GenAff.IsOnCurve())

	swG20 := sw_bn254.NewG2Affine(g20GenAff)
	swG21 := sw_bn254.NewG2Affine(g21GenAff)

	witnessCircuit.G2Points = [2]*sw_bn254.G2Affine{&swG20, &swG21}

	err = test.IsSolved(&circuit, &witnessCircuit, ecc.BN254.ScalarField())
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
	assert.True(g20.IsOnCurve())

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
	assert.True(g21.IsOnCurve())
}
