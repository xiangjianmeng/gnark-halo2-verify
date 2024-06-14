package main

import (
	"crypto/rand"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
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
