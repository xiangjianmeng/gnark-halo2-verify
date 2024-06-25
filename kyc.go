package main

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

type Conditions struct {
	Age     [2]frontend.Variable
	Country []frontend.Variable
	Level   []frontend.Variable
	Time    []frontend.Variable
}

type KycType struct {
	Age     frontend.Variable
	Country frontend.Variable
	Level   frontend.Variable
	Time    frontend.Variable
}

type Circuit struct {
	Signature     ecdsa.Signature[emulated.Secp256k1Fr]
	KycHash       emulated.Element[emulated.Secp256k1Fr]
	Kyc           KycType
	ConditionHash Conditions `gnark:",public"`
}

// Define declares the circuit logic. The compiler then produces a list of constraints
// which must be satisfied (valid witness) in order to create a valid zk-SNARK
// This circuit verifies an EdDSA signature.
func (circuit *Circuit) Define(api frontend.API) error {
	x, ok := big.NewInt(0).SetString("85997066971194522473057012223499312995837068047270353161199320975157154592866", 10)
	if !ok {
		panic("invalid value")
	}

	y, ok := big.NewInt(0).SetString("40070151623224504185408656535330873345235311800089295101492157067180406840001", 10)
	if !ok {
		panic("invalid value")
	}

	pubKey := ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		X: emulated.ValueOf[emulated.Secp256k1Fp](x),
		Y: emulated.ValueOf[emulated.Secp256k1Fp](y),
	}

	pubKey.Verify(api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp](), &circuit.KycHash, &circuit.Signature)

	err := VerifyRangeCheck(api, circuit.Kyc.Age, circuit.ConditionHash.Age[0], circuit.ConditionHash.Age[1])
	if err != nil {
		return err
	}

	isInList := frontend.Variable(0)
	for _, country := range circuit.ConditionHash.Country {
		match := api.IsZero(api.Sub(circuit.Kyc.Country, country))
		isInList = api.Or(isInList, match)
	}
	api.AssertIsEqual(isInList, frontend.Variable(1))

	return nil
}
