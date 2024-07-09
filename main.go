// Welcome to the gnark playground!
package main

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/solidity"
	gnarkio "github.com/consensys/gnark/io"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	//"github.com/consensys/gnark/test/unsafekzg"
	"gnark-halo2-verify/circuit"
)

func main() {
	var (
		backendID       = backend.GROTH16
		curveID         = ecc.BN254
		concreteBackend circuit.Backend
	)

	var aggCircuit = circuit.AggregatorCircuit{
		Proof:      make([]frontend.Variable, len(circuit.ProofStr)),
		VerifyInst: make([]frontend.Variable, 1),
		Aux:        make([]frontend.Variable, len(circuit.AuxStr)),
		TargetInst: make([]frontend.Variable, 4),
	}

	// 3a. Fill witness and instance
	var witnessCircuit = circuit.AggregatorCircuit{
		Proof:      make([]frontend.Variable, len(circuit.ProofStr)),
		VerifyInst: make([]frontend.Variable, 1),
		Aux:        make([]frontend.Variable, len(circuit.AuxStr)),
		TargetInst: make([]frontend.Variable, 4),
	}

	for i := 0; i < len(circuit.ProofStr); i++ {
		proof, _ := big.NewInt(0).SetString(circuit.ProofStr[i], 10)
		witnessCircuit.Proof[i] = proof
	}
	verifyIns, _ := big.NewInt(0).SetString("10573525131658455000365299935369648652552518565632155338390913030155084554858", 10)
	witnessCircuit.VerifyInst[0] = verifyIns
	for i := 0; i < len(circuit.AuxStr); i++ {
		aux, _ := big.NewInt(0).SetString(circuit.AuxStr[i], 10)
		witnessCircuit.Aux[i] = aux
	}
	target0, _ := big.NewInt(0).SetString("7059793422771910484", 10)
	target1, _ := big.NewInt(0).SetString("2556686405730241944", 10)
	target2, _ := big.NewInt(0).SetString("2133554817341762742", 10)
	target3, _ := big.NewInt(0).SetString("8974371243071329347", 10)
	witnessCircuit.TargetInst[0] = target0
	witnessCircuit.TargetInst[1] = target1
	witnessCircuit.TargetInst[2] = target2
	witnessCircuit.TargetInst[3] = target3
	witnessCircuit.ProgramHash = new(big.Int).Mod(circuit.PackUInt64BigInt(target0, target1, target2, target3), circuit.MODULUS)

	// 1. compile
	log.Println("[Start] Compile")
	ccs, err := circuit.Compile(&aggCircuit, curveID, backendID, []frontend.CompileOption{frontend.IgnoreUnconstrainedInputs()})
	if err != nil {
		panic(err)
	}
	log.Println("[End] Compile")

	switch backendID {
	case backend.GROTH16:
		concreteBackend = circuit.GrothBackend
	case backend.PLONK:
		concreteBackend = circuit.PlonkBackend
	default:
		panic("backend not implemented")
	}

	// 2. setup
	log.Println("[Start] setup")
	pk, vk, err := concreteBackend.Setup(ccs, curveID)
	if err != nil {
		panic(err)
	}
	log.Println("[End] setup")

	var proverOpts []backend.ProverOption
	var verifierOpts []backend.VerifierOption
	if backendID == backend.GROTH16 {
		// additionally, we use sha256 as hash to field (fixed in Solidity contract)
		proverOpts = append(proverOpts, backend.WithProverHashToFieldFunction(sha256.New()))
		verifierOpts = append(verifierOpts, backend.WithVerifierHashToFieldFunction(sha256.New()))
	}

	// 3. Generate witness
	witness, err := frontend.NewWitness(&witnessCircuit, curveID.ScalarField())
	if err != nil {
		log.Fatalln(err)
	}

	// 4. Generate Proof
	log.Println("[Start] prove")
	proof, err := concreteBackend.Prove(ccs, pk, witness, proverOpts...)
	if err != nil {
		log.Fatalln(err)
	}
	proofJSON, _ := json.MarshalIndent(proof, "", "    ")
	_ = os.WriteFile("gnark_proof.json", proofJSON, 0644)
	fProof, err := os.Create("proof")
	if err != nil {
		log.Fatalln(err)
	}
	_, err = proof.(gnarkio.WriterRawTo).WriteRawTo(fProof)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("[End] proof")

	// 5. Verify Proof
	log.Println("[Start] verify")

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	s, err := frontend.NewSchema(&witnessCircuit)
	if err != nil {
		panic(err)
	}
	publicWitnessJSON, err := publicWitness.ToJSON(s)
	_ = os.WriteFile("gnark_inputs.json", publicWitnessJSON, 0644)
	fPublic, err := os.Create("public")
	if err != nil {
		log.Fatalln(err)
	}
	_, err = publicWitness.WriteTo(fPublic)
	if err != nil {
		log.Fatalln(err)
	}

	err = concreteBackend.Verify(proof, vk, publicWitness, verifierOpts...)
	if err != nil {
		panic(err)
	}
	log.Println("[End] verify")

	circuit.SolidityVerification(backendID, vk.(solidity.VerifyingKey), proof, publicWitness, nil)
}
