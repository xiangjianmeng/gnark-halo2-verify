package circuit

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"regexp"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test/unsafekzg"
)

type ProofType int

const (
	Unknown ProofType = iota
	Groth16
	Plonk
)

const (
	Groth16PkName        = "./data/groth16_pk"
	Groth16VkName        = "./data/groth16_vk"
	PlonkPkName          = "./data/plonk_pk"
	PlonkVkName          = "./data/plonk_vk"
	PlonkSrsName         = "./data/plonk_srs"
	PlonkSrsLagrangeName = "./data/plonk_srsLagrange"
	ProofJsonName        = "./data/proof.json"
	ProofName            = "./data/proof"
	InputsJsonName       = "./data/inputs.json"
	InputsName           = "./data/inputs"
	ContractName         = "./data/contract_verify.sol"
)

func ProofTypeToString(s ProofType) string {
	switch s {
	case Groth16:
		return fmt.Sprintf("Groth16")
	case Plonk:
		return fmt.Sprintf("Plonk")
	default:
		log.Fatalf("unknown proof type %d", s)
	}
	return "Groth16"
}

func GeneratePlonkPkVk(cs constraint.ConstraintSystem) (plonk.ProvingKey, plonk.VerifyingKey) {
	srs, srsLagrange, err := unsafekzg.NewSRS(cs)
	if err != nil {
		panic(err)
	}
	fSrs, err := os.Create(PlonkSrsName)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = srs.WriteRawTo(fSrs)
	if err != nil {
		log.Fatalln(err)
	}

	fSrsLagrange, err := os.Create(PlonkSrsLagrangeName)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = srsLagrange.WriteRawTo(fSrsLagrange)
	if err != nil {
		log.Fatalln(err)
	}
	pk, vk, err := plonk.Setup(cs, srs, srsLagrange)

	fpk, err := os.Create(PlonkPkName)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = pk.WriteRawTo(fpk)
	if err != nil {
		log.Fatalln(err)
	}

	fvk, err := os.Create(PlonkVkName)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = vk.WriteRawTo(fvk)
	if err != nil {
		log.Fatalln(err)
	}

	return pk, vk
}

func ReadPlonkPkVk() (plonk.ProvingKey, plonk.VerifyingKey) {
	fpk, err := os.Open(PlonkPkName)
	if err != nil {
		log.Fatalln(err)
	}
	pk := plonk.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(fpk)
	if err != nil {
		log.Fatalln(err)
	}
	fvk, err := os.Open(PlonkVkName)
	if err != nil {
		log.Fatalln(err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(fvk)
	if err != nil {
		log.Fatalln(err)
	}
	return pk, vk
}

func GenerateGrowth16PkVk(cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey) {
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}

	fpk, err := os.Create(Groth16PkName)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = pk.WriteRawTo(fpk)
	if err != nil {
		log.Fatalln(err)
	}

	fvk, err := os.Create(Groth16VkName)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = vk.WriteRawTo(fvk)
	if err != nil {
		log.Fatalln(err)
	}

	return pk, vk
}

func ReadGrowth16PkVk() (groth16.ProvingKey, groth16.VerifyingKey) {
	fpk, err := os.Open(Groth16PkName)
	if err != nil {
		log.Fatalln(err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(fpk)
	if err != nil {
		log.Fatalln(err)
	}
	fvk, err := os.Open(Groth16VkName)
	if err != nil {
		log.Fatalln(err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(fvk)
	if err != nil {
		log.Fatalln(err)
	}
	return pk, vk
}

func PackUInt8BigInt(inputs ...*big.Int) *big.Int {
	res := inputs[0]
	for _, input := range inputs[1:] {
		res = new(big.Int).Mul(res, new(big.Int).Exp(big.NewInt(2), big.NewInt(8), nil))
		res = new(big.Int).Add(res, input)
	}
	return res
}

func PackUInt64BigInt(inputs ...*big.Int) *big.Int {
	res := inputs[0]
	for _, input := range inputs[1:] {
		res = new(big.Int).Mul(res, new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil))
		res = new(big.Int).Add(res, input)
	}
	return res
}

func PackUInt64Variables(api frontend.API, inputs ...frontend.Variable) frontend.Variable {
	res := inputs[0]
	for _, input := range inputs[1:] {
		res = api.Mul(res, new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil))
		res = api.Add(res, input)
	}
	return res
}

func PackUInt8Variables(api frontend.API, inputs ...frontend.Variable) frontend.Variable {
	res := inputs[0]
	for _, input := range inputs[1:] {
		res = api.Mul(res, new(big.Int).Exp(big.NewInt(2), big.NewInt(8), nil))
		res = api.Add(res, input)
	}
	return res
}

func PackUInt128Variables(api frontend.API, inputs ...frontend.Variable) frontend.Variable {
	res := inputs[0]
	for _, input := range inputs[1:] {
		res = api.Mul(res, new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil))
		res = api.Add(res, input)
	}
	return res
}

func Div128Hint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	upper := new(big.Int).Div(inputs[0], big.NewInt(0).Lsh(big.NewInt(1), 128)) // input >> 128
	lower := new(big.Int).Mod(inputs[0], big.NewInt(0).Lsh(big.NewInt(1), 128)) // input & ((1 << 128) - 1)
	outputs[0] = upper
	outputs[1] = lower

	return nil
}

func ToElement[T emulated.FieldParams](api frontend.API, input frontend.Variable) (emulated.Element[T], error) {
	inputFiled, err := emulated.NewField[T](api)
	if err != nil {
		return emulated.Element[T]{}, err
	}

	results, err := api.Compiler().NewHint(Div128Hint, 2, input)
	if err != nil {
		return emulated.Element[T]{}, err
	}

	upperBits := api.ToBinary(results[0], 128)
	lowerBits := api.ToBinary(results[1], 128)

	// Concatenate the binary representations
	inputBits := append(lowerBits, upperBits...)

	inputEle := inputFiled.FromBits(inputBits...)
	return *inputEle, nil
}

func ToPoint[T emulated.FieldParams](api frontend.API, point [2]frontend.Variable) (sw_emulated.AffinePoint[T], error) {
	x, err := ToElement[T](api, point[0])
	if err != nil {
		return sw_emulated.AffinePoint[T]{}, err
	}
	y, err := ToElement[T](api, point[1])
	if err != nil {
		return sw_emulated.AffinePoint[T]{}, err
	}

	return sw_emulated.AffinePoint[T]{
		X: x,
		Y: y,
	}, nil
}

func extractAndConvert(input string) (string, string, error) {
	re := regexp.MustCompile(`bn256\.G1\((\w+),\s(\w+)\)`)

	matches := re.FindStringSubmatch(input)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid input format")
	}

	xStr := matches[1]
	yStr := matches[2]

	x10Str, err := hexToDecimalString(xStr)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode x: %v", err)
	}

	y10Str, err := hexToDecimalString(yStr)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode y: %v", err)
	}

	return x10Str, y10Str, nil
}

// Converts hex string to decimal string
func hexToDecimalString(hexStr string) (string, error) {
	// Strip leading "0x" if it exists
	hexStr = strings.TrimPrefix(hexStr, "0x")

	// Convert hex to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	// Convert bytes to big.Int
	bigInt := new(big.Int).SetBytes(bytes)

	// Convert big.Int to decimal string
	return bigInt.String(), nil
}
