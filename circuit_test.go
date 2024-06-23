package main

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	//"github.com/consensys/gnark/std/hash/sha3"
	crysha3 "golang.org/x/crypto/sha3"
)

func TestSha3(t *testing.T) {
	assert := test.NewAssert(t)
	input, succ := new(big.Int).SetString("21018549926786911420919261871844456760738199621624594828144407595472474813958", 10)
	assert.True(succ)

	inputBytes := input.FillBytes(make([]byte, 32))

	ethHashVal := crypto.Keccak256Hash(inputBytes)

	hasher := crysha3.NewLegacyKeccak256()
	hasher.Write(inputBytes)
	cryHashVal := hasher.Sum(nil)

	assert.Equal(ethHashVal.Bytes(), cryHashVal, "wrong hash")
}

func TestOnBn254(t *testing.T) {
	x := new(big.Int)
	y := new(big.Int)

	x.SetString("13534086339230182803823178260078315691269243572458753455438283544709107378988", 10)
	y.SetString("9053077977614827188269653632534212501565186534180282672519599630892718179094", 10)

	// Define the curve modulus and b parameter
	q := new(big.Int)
	q.SetString(FrModulus, 10)

	// Define x^3 + 3
	xCubed := new(big.Int).Exp(x, big.NewInt(3), q)
	xCubed.Add(xCubed, big.NewInt(3))
	xCubed.Mod(xCubed, q)

	// Define y^2
	ySquared := new(big.Int).Mul(y, y)
	ySquared.Mod(ySquared, q)

	if xCubed.Cmp(ySquared) == 0 {
		fmt.Println("The point is on the BN256 curve")
	} else {
		fmt.Println("The point is NOT on the BN256 curve")
	}
}

func TestCircuit(t *testing.T) {
	grkAssert := test.NewAssert(t)

	var witnessCircuit = AggregatorCircuit{
		Proof:      make([]frontend.Variable, len(proofStr)),
		VerifyInst: make([]frontend.Variable, 1),
		Aux:        make([]frontend.Variable, len(auxStr)),
		TargetInst: make([]frontend.Variable, 4),
	}

	for i := 0; i < len(proofStr); i++ {
		proof, _ := big.NewInt(0).SetString(proofStr[i], 10)
		witnessCircuit.Proof[i] = proof
	}
	verifyIns, _ := big.NewInt(0).SetString("10573525131658455000365299935369648652552518565632155338390913030155084554858", 10)
	witnessCircuit.VerifyInst[0] = verifyIns
	for i := 0; i < len(auxStr); i++ {
		aux, _ := big.NewInt(0).SetString(auxStr[i], 10)
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

	err := test.IsSolved(&witnessCircuit, &witnessCircuit, ecc.BN254.ScalarField())
	grkAssert.NoError(err)
}
