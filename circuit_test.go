package main

import (
	"crypto/rand"
	"fmt"
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
	p := new(big.Int)
	p.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	// Define x^3 + 3
	xCubed := new(big.Int).Exp(x, big.NewInt(3), p)
	xCubed.Add(xCubed, big.NewInt(3))
	xCubed.Mod(xCubed, p)

	// Define y^2
	ySquared := new(big.Int).Mul(y, y)
	ySquared.Mod(ySquared, p)

	if xCubed.Cmp(ySquared) == 0 {
		fmt.Println("The point is on the BN256 curve")
	} else {
		fmt.Println("The point is NOT on the BN256 curve")
	}
}
