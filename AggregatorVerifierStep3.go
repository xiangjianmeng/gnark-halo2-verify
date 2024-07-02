package main

import (
	"github.com/consensys/gnark/frontend"
	"math/big"
)

func VerifyProof3(
	api frontend.API,
	transcript []frontend.Variable,
	aux []frontend.Variable,
	buf [43]frontend.Variable,
) ([43]frontend.Variable, error) {
	//frOne, _ := new(big.Int).SetString("1", 10)
	buf[14], buf[15] = transcript[40], transcript[41]
	buf[16] = fr_mul(api, buf[17], buf[35])
	err := ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[38], transcript[39]
	buf[16] = buf[17]
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = buf[0], buf[1]
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[30], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[17] = fr_mul(api,
		fr_mul(api, buf[19], buf[8]),
		buf[28],
	)
	buf[14], buf[15] = transcript[16], transcript[17]
	buf[16] = fr_mul(api, buf[17], buf[7])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[20] = fr_mul(api, buf[20], buf[23])
	buf[14], buf[15] = transcript[18], transcript[19]
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[20], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[32], transcript[33]
	buf[16] = fr_mul(api, buf[25], buf[7])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[20], transcript[21]
	buf[16] = buf[17]
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[22], transcript[23]
	buf[16] = fr_mul(api, buf[21], buf[20])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[34], transcript[35]
	buf[16] = buf[25]
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	constFr, _ := new(big.Int).SetString("14330957265734295635487529150089503047509680887155412481838936779763595454159", 10)
	constFr1, _ := new(big.Int).SetString("11657029790297552620042403612079612021781553164410884915460958808861335447799", 10)
	buf[14], buf[15] = constFr, constFr1
	buf[16] = fr_mul(api, buf[21], buf[26])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[17] = fr_mul(api, buf[24], buf[23])
	constFr, _ = new(big.Int).SetString("3217632689962165131030083420553195932069690674124201615821228288158667916559", 10)
	constFr1, _ = new(big.Int).SetString("11279851209809827628209572028517900058696331891386803672043677236706605258017", 10)
	buf[14], buf[15] = constFr, constFr1
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[17], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	constFr, _ = new(big.Int).SetString("6052548824579324632823008857297151984962554125394528409163563861993455062230", 10)
	constFr1, _ = new(big.Int).SetString("5253299219790956244634070239415866732913146545893144333850618503587190167918", 10)
	buf[14], buf[15] = constFr, constFr1
	buf[16] = fr_mul(api, buf[21], buf[17])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	constFr, _ = new(big.Int).SetString("20134811260136067172423268982757475565512657205230154765724273546621797752349", 10)
	constFr1, _ = new(big.Int).SetString("6892971650116630821526804754060441250258363920342589425839414580605638919318", 10)
	buf[14], buf[15] = constFr, constFr1
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[24], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	constFr, _ = new(big.Int).SetString("17209526517725877136177243553045588666670528061781328851527842192340596792007", 10)
	constFr1, _ = new(big.Int).SetString("673380535462416015709313880421335139519451950072360935904307055208109203957", 10)
	buf[14], buf[15] = constFr, constFr1
	buf[16] = fr_mul(api, buf[21], buf[24])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	constFr, _ = new(big.Int).SetString("9973741392326192617521393709476164203221054644042980686853312098867551316157", 10)
	constFr1, _ = new(big.Int).SetString("9696890272060053851986158851707718469926088811173404342570425124396426957984", 10)
	buf[14], buf[15] = constFr, constFr1
	buf[16] = fr_mul(api, buf[21], buf[31])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	constFr, _ = new(big.Int).SetString("14118917696035322873139367456503207319385222068825598680486765986706935215403", 10)
	constFr1, _ = new(big.Int).SetString("18580702656451937158771044279900207779359395181895031379070145857747412641911", 10)
	buf[14], buf[15] = constFr, constFr1
	buf[16] = fr_mul(api, buf[21], buf[23])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[17] = fr_mul(api, buf[19], buf[19])
	buf[14], buf[15] = transcript[24], transcript[25]
	buf[16] = fr_mul(api, buf[17], buf[23])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[26], transcript[27]
	buf[16] = fr_mul(api, buf[17], buf[7])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[28], transcript[29]
	buf[16] = buf[17]
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[30], transcript[31]
	buf[16] = fr_mul(api, buf[25], buf[23])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[36], transcript[37]
	buf[16] = buf[21]
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}

	return buf, nil
}
