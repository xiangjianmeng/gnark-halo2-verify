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
		TargetInst: make([]frontend.Variable, 1),
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &aggCircuit)
	//fmt.Println(p.NbConstraints())
	//fmt.Println(p.Top())

	//r, ok := big.NewInt(0).SetString("45536044045135930417610581277973574046122438970391757925449844580498097416238", 10)
	//if !ok {
	//	panic("invalid value")
	//}

	//s, ok := big.NewInt(0).SetString("77405625560525123464152303145240770328705524946250305291099118722847750339975", 10)
	//if !ok {
	//	panic("invalid value")
	//}
	//
	//x, ok := big.NewInt(0).SetString("85997066971194522473057012223499312995837068047270353161199320975157154592866", 10)
	//if !ok {
	//	panic("invalid value")
	//}
	//
	//y, ok := big.NewInt(0).SetString("40070151623224504185408656535330873345235311800089295101492157067180406840001", 10)
	//if !ok {
	//	panic("invalid value")
	//}
	//
	//hash, ok := big.NewInt(0).SetString("65836751601596300032969389553597263219621359970931417026813124302429596772205", 10)
	////hash, ok := big.NewInt(0).SetString("55836751601596300032969389553597263219621359970931417026813124302429596772205", 10)
	//if !ok {
	//	panic("invalid value")
	//}

	log.Println("start setup")

	// 1. One time setup
	//pk, vk, err := groth16.Setup(r1cs)
	//if err != nil {
	//	panic(err)
	//}

	srs, srsLagrange, err := unsafekzg.NewSRS(r1cs)

	pk, vk, err := plonk.Setup(r1cs, srs, srsLagrange)

	if err != nil {
		panic(err)
	}

	log.Println("end setup")

	var witnessCircuit = AggregatorCircuit{
		Proof:      make([]frontend.Variable, 1),
		VerifyInst: make([]frontend.Variable, 1),
		Aux:        make([]frontend.Variable, 1),
		TargetInst: make([]frontend.Variable, 1),
	}
	witnessCircuit.Proof[0] = frontend.Variable(big.NewInt(100))
	witnessCircuit.VerifyInst[0] = frontend.Variable(big.NewInt(100))
	witnessCircuit.Aux[0] = frontend.Variable(big.NewInt(100))
	witnessCircuit.TargetInst[0] = frontend.Variable(big.NewInt(100))

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
