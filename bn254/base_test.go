package bn254

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
)

type TestBn254RangeCheckCircuit struct {
	X frontend.Variable
}

func (c *TestBn254RangeCheckCircuit) Define(api frontend.API) error {
	glApi := New(api)
	glApi.RangeCheck(NewVariable(c.X))
	return nil
}
func TestBn254RangeCheck(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TestBn254RangeCheckCircuit

	witness.X = 1
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	witness.X = 0
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	witness.X = MODULUS
	assert.ProverFailed(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoSerializationChecks())

	one := big.NewInt(1)
	maxValidVal := new(big.Int).Sub(MODULUS, one)
	witness.X = maxValidVal
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

type TestBn254RangeCheckBenchmarkCircuit struct {
	X []frontend.Variable
}

func (c *TestBn254RangeCheckBenchmarkCircuit) Define(api frontend.API) error {
	glApi := New(api)
	for _, x := range c.X {
		glApi.RangeCheck(NewVariable(x))
		glApi.Reduce(NewVariable(x))

	}
	return nil
}

func BenchmarkGoldilocksRangeCheck(b *testing.B) {
	var sizes = []int{5, 10, 15}
	for i := 0; i < len(sizes); i++ {
		var circuit, witness TestBn254RangeCheckBenchmarkCircuit
		circuit.X = make([]frontend.Variable, 2<<sizes[i])
		witness.X = make([]frontend.Variable, 2<<sizes[i])
		for j := 0; j < len(circuit.X); j++ {
			witness.X[j] = 1
		}
		p := profile.Start()
		r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
		if err != nil {
			fmt.Println("error in building circuit", err)
			os.Exit(1)
		}
		p.Stop()
		p.Top()
		println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
		println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
		println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
		println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
		println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())
	}
}

type TestBn254MulAddCircuit struct {
	X, Y, Z        frontend.Variable
	ExpectedResult frontend.Variable
}

func (c *TestBn254MulAddCircuit) Define(api frontend.API) error {
	glApi := New(api)
	calculateValue := glApi.MulAdd(NewVariable(c.X), NewVariable(c.Y), NewVariable(c.Z))
	api.AssertIsEqual(calculateValue.Limb, c.ExpectedResult)
	return nil
}

func TestBn254MulAdd(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness TestBn254MulAddCircuit

	witness.X = 1
	witness.Y = 2
	witness.Z = 3
	witness.ExpectedResult = 5
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())

	bigOperand := new(big.Int).SetUint64(9223372036854775808)
	expectedValue, _ := new(big.Int).SetString("18446744068340842500", 10)

	witness.X = bigOperand
	witness.Y = bigOperand
	witness.Z = 3
	witness.ExpectedResult = expectedValue
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.NoFuzzing())
}
