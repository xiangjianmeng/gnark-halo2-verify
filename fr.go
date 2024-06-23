package main

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func ecc_mul(api frontend.API, input []frontend.Variable, offset int) error {
	//if input[offset+2].(*big.Int) == fr_from_string("1") {
	//	return nil
	//}
	//
	one := fr_from_string("1")
	//cmp := api.Cmp(input[offset+2], one)
	if input[offset+2].(*big.Int).Cmp(one.(*big.Int)) == 0 {
		return nil
	}

	res, err := CalcVerifyBN256Msm(api, input[offset], input[offset+1], input[offset+2])
	if err != nil {
		return err
	}
	input[offset] = res[0]
	input[offset+1] = res[1]
	return nil
}

func ecc_mul_add(api frontend.API, buf []frontend.Variable, offset int) error {
	err := ecc_mul(api, buf, offset+2)
	if err != nil {
		return err
	}

	res, err := CalcVerifyBN256Add(api, buf[offset], buf[offset+1], buf[offset+2], buf[offset+3])
	buf[offset] = res[0]
	buf[offset+1] = res[1]
	return nil
}

func fr_pow(api frontend.API, a frontend.Variable, power frontend.Variable) frontend.Variable {
	res := a
	for i := new(big.Int).SetUint64(1); i.Cmp(power.(*big.Int)) < 0; {
		i = i.Add(i, big.NewInt(1))
		res = api.Mul(res, a)
	}

	return mod(api, res)
}

func fr_mul(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	product := api.Mul(a, b)
	return mod(api, product)
}

func mod(api frontend.API, a frontend.Variable) frontend.Variable {
	aInt := a.(*big.Int)
	d := new(big.Int).Div(aInt, MODULUS)
	r := new(big.Int).Mod(aInt, MODULUS)
	api.AssertIsEqual(api.Add(r, api.Mul(d, MODULUS)), a)
	return r
}

func fr_mul_neg(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	tmp := fr_mul(api, a, b)
	return new(big.Int).Sub(MODULUS, tmp.(*big.Int))
}

func fr_add(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	sum := api.Add(a, b)
	return mod(api, sum)
}

func fr_sub(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	dec := api.Sub(a, b)
	return mod(api, dec)
}

func fr_div(api frontend.API, a frontend.Variable, b frontend.Variable, aux frontend.Variable) frontend.Variable {
	r := fr_mul(api, b, aux)
	api.AssertIsEqual(r, a)
	return mod(api, aux)
}

func fr_neg(api frontend.API, a frontend.Variable) frontend.Variable {
	return api.Sub(MODULUS, a)
}

func fr_from_string(str string) frontend.Variable {
	ele, _ := new(big.Int).SetString(str, 10)
	return ele
}
