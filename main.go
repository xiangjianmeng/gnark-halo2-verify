// Welcome to the gnark playground!
package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	//"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	//"github.com/consensys/gnark/test/unsafekzg"
	"gnark-halo2-verify/circuit"
)

func main() {
	var aggCircuit = circuit.AggregatorCircuit{
		Proof:      make([]frontend.Variable, len(circuit.ProofStr)),
		VerifyInst: make([]frontend.Variable, 1),
		Aux:        make([]frontend.Variable, len(circuit.AuxStr)),
		TargetInst: make([]frontend.Variable, 4),
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &aggCircuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		panic(err)
	}

	log.Println("start setup")

	//pk, vk := circuit.GenerateGrowth16PkVk(cs)
	//pk, vk := ReadGrowth16PkVk()

	//pk, vk := circuit.GeneratePlonkPkVk(cs)
	pk, vk := circuit.ReadPlonkPkVk()

	log.Println("end setup")

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

	witness, err := frontend.NewWitness(&witnessCircuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	log.Println("start proof")

	// 2. Proof creation
	proof, err := plonk.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}
	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity()")
	}
	proofStr := hex.EncodeToString(_proof.MarshalSolidity())
	log.Println(proofStr)

	proofJSON, _ := json.MarshalIndent(proof, "", "    ")
	_ = os.WriteFile(circuit.ProofJsonName, proofJSON, 0644)
	fProof, err := os.Create(circuit.ProofName)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = proof.WriteRawTo(fProof)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("end proof")

	log.Println("start verify")

	// 3. Proof verification
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	s, err := frontend.NewSchema(&witnessCircuit)
	if err != nil {
		panic(err)
	}
	publicWitnessJSON, err := publicWitness.ToJSON(s)
	_ = os.WriteFile(circuit.InputsJsonName, publicWitnessJSON, 0644)
	fPublic, err := os.Create(circuit.InputsName)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = publicWitness.WriteTo(fPublic)
	if err != nil {
		log.Fatalln(err)
	}

	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	f, err := os.Create(circuit.ContractName)
	if err != nil {
		log.Fatalln(err)
	}
	err = vk.ExportSolidity(f)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("end verify")
}
