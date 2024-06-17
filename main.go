// Welcome to the gnark playground!
package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"math/big"

	//"github.com/consensys/gnark/frontend/cs/r1cs"
	//"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	//"github.com/consensys/gnark/std/math/emulated"
	//"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test/unsafekzg"

	"log"
)

func main() {
	var aggCircuit = AggregatorCircuit{
		Proof:      make([]frontend.Variable, 1),
		VerifyInst: make([]frontend.Variable, 1),
		Aux:        make([]frontend.Variable, 1),
		TargetInst: make([]frontend.Variable, 4),
	}

	var witnessCircuit = AggregatorCircuit{
		Proof:      make([]frontend.Variable, 1),
		VerifyInst: make([]frontend.Variable, 1),
		Aux:        make([]frontend.Variable, 1),
		TargetInst: make([]frontend.Variable, 4),
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &aggCircuit)
	if err != nil {
		panic(err)
	}

	log.Println("start setup")

	srs, srsLagrange, err := unsafekzg.NewSRS(r1cs)
	if err != nil {
		panic(err)
	}

	pk, vk, err := plonk.Setup(r1cs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	log.Println("end setup")

	witnessCircuit.Proof[0] = frontend.Variable(big.NewInt(100))
	verifyIns, _ := big.NewInt(0).SetString("10573525131658455000365299935369648652552518565632155338390913030155084554858", 10)
	witnessCircuit.VerifyInst[0] = frontend.Variable(verifyIns)
	witnessCircuit.Aux[0] = frontend.Variable(big.NewInt(100))
	target0, _ := big.NewInt(0).SetString("7059793422771910484", 10)
	target1, _ := big.NewInt(0).SetString("2556686405730241944", 10)
	target2, _ := big.NewInt(0).SetString("2133554817341762742", 10)
	target3, _ := big.NewInt(0).SetString("8974371243071329347", 10)
	witnessCircuit.TargetInst[0] = frontend.Variable(target0)
	witnessCircuit.TargetInst[1] = frontend.Variable(target1)
	witnessCircuit.TargetInst[2] = frontend.Variable(target2)
	witnessCircuit.TargetInst[3] = frontend.Variable(target3)

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
