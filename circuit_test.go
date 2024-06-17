package main

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"testing"

	//"github.com/consensys/gnark/std/hash/sha3"
	crysha3 "golang.org/x/crypto/sha3"
)

func TestSha3(t *testing.T) {
	assert := test.NewAssert(t)
	in := make([]byte, 310)
	_, err := rand.Reader.Read(in)
	assert.NoError(err)

	ethHashVal := crypto.Keccak256Hash(in)

	hasher := crysha3.NewLegacyKeccak256()
	hasher.Write(in)
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

	err := test.IsSolved(&aggCircuit, &witnessCircuit, ecc.BN254.ScalarField())
	assert := test.NewAssert(t)
	assert.NoError(err)
}
