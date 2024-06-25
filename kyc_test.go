package main

import (
	"log"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test/unsafekzg"
)

func TestKyc(t *testing.T) {
	var eddsaCircuit = Circuit{
		ConditionHash: Conditions{
			Age:     [2]frontend.Variable{},
			Country: make([]frontend.Variable, 5),
			Level:   make([]frontend.Variable, 1),
			Time:    make([]frontend.Variable, 1),
		},
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &eddsaCircuit)

	r, ok := big.NewInt(0).SetString("45536044045135930417610581277973574046122438970391757925449844580498097416238", 10)
	if !ok {
		panic("invalid value")
	}

	s, ok := big.NewInt(0).SetString("77405625560525123464152303145240770328705524946250305291099118722847750339975", 10)
	if !ok {
		panic("invalid value")
	}

	hash, ok := big.NewInt(0).SetString("65836751601596300032969389553597263219621359970931417026813124302429596772205", 10)
	//hash, ok := big.NewInt(0).SetString("55836751601596300032969389553597263219621359970931417026813124302429596772205", 10)
	if !ok {
		panic("invalid value")
	}

	var witnessCircuit = Circuit{
		Signature: ecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		KycHash: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		ConditionHash: Conditions{
			Age:     [2]frontend.Variable{},
			Country: make([]frontend.Variable, 5),
			Level:   make([]frontend.Variable, 1),
			Time:    make([]frontend.Variable, 1),
		},
	}
	witnessCircuit.ConditionHash.Age = [2]frontend.Variable{18, 50}
	witnessCircuit.Kyc.Age = frontend.Variable(35)
	witnessCircuit.ConditionHash.Country = []frontend.Variable{100, 200, 300, 400, 500}
	witnessCircuit.Kyc.Country = frontend.Variable(300)
	witnessCircuit.ConditionHash.Level = []frontend.Variable{3}
	witnessCircuit.Kyc.Level = frontend.Variable(3)
	witnessCircuit.ConditionHash.Time = []frontend.Variable{300}
	witnessCircuit.Kyc.Time = frontend.Variable(200)

	log.Println("start setup")

	srs, srsLagrange, err := unsafekzg.NewSRS(r1cs)

	pk, vk, err := plonk.Setup(r1cs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	log.Println("end setup")

	witness, err := frontend.NewWitness(&witnessCircuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	log.Println("start proof")

	// 2. Proof creation
	proof, err := plonk.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	log.Println("end proof")

	log.Println("start verify")

	// 3. Proof verification
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	log.Println("end verify")
}
