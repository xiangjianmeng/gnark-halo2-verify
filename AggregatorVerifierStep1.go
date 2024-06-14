package main

//func eccMul(input []*big.Int, offset uint64) {
//	if input[offset+2] == big.NewInt(1) {
//		return
//	}
//
//	return msm(input, offset, 1)
//}
//
//func verifyProof(
//	transcript []*big.Int,
//	aux []*big.Int,
//	buf []*big.Int,
//) []big.Int {
//	buf[10] = transcript[102]
//	buf[11] = transcript[103]
//	buf[12] = big.NewInt(1)
//
//	eccMul(buf, 10)
//}
