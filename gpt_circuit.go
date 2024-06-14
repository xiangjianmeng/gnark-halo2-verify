package main

//
//import (
//	"github.com/consensys/gnark/frontend"
//	"github.com/consensys/gnark/std/math/bits"
//	"github.com/consensys/gnark/std/permutation/keccakf"
//)
//
//type Keccak256Circuit struct {
//	PreImage []frontend.Variable  // byte array
//	Hash     [4]frontend.Variable `gnark:",public"`
//}
//
//func padWith0x1(api frontend.API, i1 frontend.Variable, pos int) frontend.Variable {
//	lastUint64Binary := api.ToBinary(i1, 64)
//	lastUint64Binary[(pos)*8] = 1
//	return api.FromBinary(lastUint64Binary...)
//}
//
//func (c *Keccak256Circuit) Define(api frontend.API) error {
//	return VerifyKeccak2561(api, c.PreImage, c.Hash)
//}
//
//func VerifyKeccak2561(
//	api frontend.API,
//	PreImage []frontend.Variable,
//	Hash [4]frontend.Variable,
//) error {
//	inputSizeInBytes := len(PreImage)
//
//	var state [25]frontend.Variable
//	for i := range state {
//		state[i] = 0
//	}
//
//	inputSizeInUint64 := (inputSizeInBytes + 8 - 1) / 8
//	paddedPreImageLength := inputSizeInUint64 + 17 - (inputSizeInUint64 % 17)
//	paddedPreImage := make([]frontend.Variable, paddedPreImageLength)
//	for i := 0; i < inputSizeInUint64; i++ {
//		binUint64 := make([]frontend.Variable, 0)
//		for j := 0; j < 8; j++ {
//			if i*8+j < inputSizeInBytes {
//				binUint64 = append(binUint64, api.ToBinary(PreImage[i*8+j], 8)...)
//			} else {
//				binUint64 = append(binUint64, api.ToBinary(0, 8)...)
//			}
//		}
//		paddedPreImage[i] = api.FromBinary(binUint64...)
//	}
//	for i := inputSizeInUint64; i < paddedPreImageLength; i++ {
//		paddedPreImage[i] = 0
//	}
//
//	lastUint64ByteCount := inputSizeInBytes % 8
//	if lastUint64ByteCount > 0 {
//		paddedPreImage[inputSizeInUint64-1] = padWith0x1(api, paddedPreImage[inputSizeInUint64-1], lastUint64ByteCount)
//	} else {
//		paddedPreImage[inputSizeInUint64] = padWith0x1(api, paddedPreImage[inputSizeInUint64], lastUint64ByteCount)
//	}
//
//	toPad := api.ToBinary(paddedPreImage[paddedPreImageLength-1], 64)
//	toPad[63] = 1
//	paddedPreImage[paddedPreImageLength-1] = api.FromBinary(toPad...)
//
//	uapi := newUint64API(api)
//	for i := 0; i < len(paddedPreImage); i += 17 {
//		for j := 0; j < 17; j++ {
//			state[j] = uapi.fromUint64(uapi.xor(uapi.asUint64(state[j]), uapi.asUint64(paddedPreImage[i+j])))
//		}
//		state = keccakf.Permute(api, state)
//	}
//
//	for j := 0; j < 4; j++ {
//		api.AssertIsEqual(state[j], Hash[j])
//	}
//	return nil
//}
//
//// uint64api performs binary operations on xuint64 variables. In the
//// future possibly using lookup tables.
////
//// TODO: we could possibly optimise using hints if working over many inputs. For
//// example, if we OR many bits, then the result is 0 if the sum of the bits is
//// larger than 1. And AND is 1 if the sum of bits is the number of inputs. BUt
//// this probably helps only if we have a lot of similar operations in a row
//// (more than 4). We could probably unroll the whole permutation and expand all
//// the formulas to see. But long term tables are still better.
//type uint64api struct {
//	api frontend.API
//}
//
//func newUint64API(api frontend.API) *uint64api {
//	return &uint64api{
//		api: api,
//	}
//}
//
//// varUint64 represents 64-bit unsigned integer. We use this type to ensure that
//// we work over constrained bits. Do not initialize directly, use [wideBinaryOpsApi.asUint64].
//type xuint64 [64]frontend.Variable
//
//func constUint64(a uint64) xuint64 {
//	var res xuint64
//	for i := 0; i < 64; i++ {
//		res[i] = (a >> i) & 1
//	}
//	return res
//}
//
//func (w *uint64api) asUint64(in frontend.Variable) xuint64 {
//	bits := bits.ToBinary(w.api, in, bits.WithNbDigits(64))
//	var res xuint64
//	copy(res[:], bits)
//	return res
//}
//
//func (w *uint64api) fromUint64(in xuint64) frontend.Variable {
//	return bits.FromBinary(w.api, in[:], bits.WithUnconstrainedInputs())
//}
//
//func (w *uint64api) and(in ...xuint64) xuint64 {
//	var res xuint64
//	for i := range res {
//		res[i] = 1
//	}
//	for i := range res {
//		for _, v := range in {
//			res[i] = w.api.And(res[i], v[i])
//		}
//	}
//	return res
//}
//
//func (w *uint64api) xor(in ...xuint64) xuint64 {
//	var res xuint64
//	for i := range res {
//		res[i] = 0
//	}
//	for i := range res {
//		for _, v := range in {
//			res[i] = w.api.Xor(res[i], v[i])
//		}
//	}
//	return res
//}
//
//func (w *uint64api) lrot(in xuint64, shift int) xuint64 {
//	var res xuint64
//	for i := range res {
//		res[i] = in[(i-shift+64)%64]
//	}
//	return res
//}
//
//func (w *uint64api) not(in xuint64) xuint64 {
//	// TODO: it would be better to have separate method for it. If we have
//	// native API support, then in R1CS would be free (1-X) and in PLONK 1
//	// constraint (1-X). But if we do XOR, then we always have a constraint with
//	// R1CS (not sure if 1-2 with PLONK). If we do 1-X ourselves, then compiler
//	// marks as binary which is 1-2 (R1CS-PLONK).
//	var res xuint64
//	for i := range res {
//		res[i] = w.api.Xor(in[i], 1)
//	}
//	return res
//}
//
//func (w *uint64api) assertEq(a, b xuint64) {
//	for i := range a {
//		w.api.AssertIsEqual(a[i], b[i])
//	}
//}
