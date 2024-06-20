package main

import (
	"github.com/consensys/gnark/frontend"
	"math/big"
)

func VerifyProof2(
	api frontend.API,
	transcript []frontend.Variable,
	aux []frontend.Variable,
	buf [43]frontend.Variable,
) ([43]frontend.Variable, error) {
	frOne, _ := new(big.Int).SetString("1", 10)
	buf[39] = fr_mul(api,
		fr_add(api,
			fr_mul(api,
				fr_mul(api,
					transcript[91],
					fr_add(api, transcript[92], buf[3]),
				),
				fr_add(api, transcript[94], buf[4]),
			),
			fr_neg(api, buf[39]),
		),
		buf[38],
	)
	buf[40] = fr_add(api,
		transcript[92],
		fr_neg(api, transcript[94]),
	)
	buf[31] = fr_mul(api,
		fr_add(api,
			fr_mul(api,
				fr_add(api,
					fr_mul(api, buf[31], buf[5]),
					buf[39],
				),
				buf[5],
			),
			fr_mul(api, buf[37], buf[40]),
		),
		buf[5],
	)
	buf[31] = fr_mul(api,
		fr_add(api,
			buf[31],
			fr_mul(api,
				fr_mul(api,
					buf[40],
					fr_add(api,
						transcript[92],
						fr_neg(api, transcript[93]),
					),
				),
				buf[38],
			),
		),
		buf[5],
	)
	buf[31] = fr_add(api,
		fr_mul(api,
			fr_add(api,
				buf[31],
				fr_mul(api,
					buf[37],
					fr_add(api,
						frOne,
						fr_neg(api, transcript[95]),
					),
				),
			),
			buf[5],
		),
		fr_mul(api,
			buf[33],
			fr_add(api,
				fr_mul(api, transcript[95], transcript[95]),
				fr_neg(api, transcript[95]),
			),
		),
	)

	constFr, _ := new(big.Int).SetString("18", 10)
	buf[33] = fr_mul(api,
		fr_mul(api,
			transcript[95],
			fr_add(api,
				fr_add(api,
					fr_mul(api, *constFr, buf[2]),
					transcript[53],
				),
				buf[3],
			),
		),
		buf[34],
	)
	buf[33] = fr_mul(api,
		fr_add(api,
			fr_mul(api,
				fr_mul(api,
					transcript[96],
					fr_add(api, transcript[97], buf[3]),
				),
				fr_add(api, transcript[99], buf[4]),
			),
			fr_neg(api, buf[33]),
		),
		buf[38],
	)
	buf[34] = fr_add(api,
		transcript[97],
		fr_neg(api, transcript[99]),
	)
	buf[31] = fr_mul(api,
		fr_add(api,
			fr_mul(api,
				fr_add(api,
					fr_mul(api, buf[31], buf[5]),
					buf[33],
				),
				buf[5],
			),
			fr_mul(api, buf[37], buf[34]),
		),
		buf[5],
	)
	buf[31] = fr_div(api,
		fr_add(api,
			buf[31],
			fr_mul(api,
				fr_mul(api,
					buf[34],
					fr_add(api,
						transcript[97],
						fr_neg(api, transcript[98]),
					),
				),
				buf[38],
			),
		),
		buf[36],
		aux[16],
	)
	buf[20] = fr_mul(api, buf[17], buf[20])
	buf[33] = fr_mul(api,
		fr_mul(api,
			fr_mul(api, buf[20], buf[22]),
			buf[25],
		),
		buf[27],
	)
	buf[18] = fr_add(api,
		fr_mul(api,
			buf[8],
			fr_add(api,
				fr_mul(api, buf[8], buf[18]),
				fr_mul(api, buf[21], buf[28]),
			),
		),
		fr_mul(api,
			fr_add(api,
				fr_mul(api,
					buf[7],
					fr_add(api, buf[29], buf[31]),
				),
				transcript[71],
			),
			buf[33],
		),
	)
	buf[21] = fr_neg(api, buf[30])
	buf[29] = fr_neg(api, buf[32])
	buf[30] = fr_mul(api,
		buf[7],
		fr_add(api,
			fr_mul(api,
				fr_add(api,
					fr_mul(api, buf[23], transcript[49]),
					fr_mul(api, buf[26], transcript[50]),
				),
				buf[9],
			),
			fr_add(api,
				fr_mul(api, buf[21], transcript[49]),
				fr_mul(api, buf[29], transcript[50]),
			),
		),
	)
	buf[30] = fr_add(api,
		buf[30],
		fr_add(api,
			fr_mul(api,
				fr_add(api,
					fr_mul(api, buf[23], transcript[88]),
					fr_mul(api, buf[26], transcript[89]),
				),
				buf[9],
			),
			fr_add(api,
				fr_mul(api, buf[21], transcript[88]),
				fr_mul(api, buf[29], transcript[89]),
			),
		),
	)
	buf[30] = fr_add(api,
		fr_mul(api, buf[7], buf[30]),
		fr_add(api,
			fr_mul(api,
				fr_add(api,
					fr_mul(api, buf[23], transcript[90]),
					fr_mul(api, buf[26], transcript[91]),
				),
				buf[9],
			),
			fr_add(api,
				fr_mul(api, buf[21], transcript[90]),
				fr_mul(api, buf[29], transcript[91]),
			),
		),
	)
	buf[30] = fr_add(api,
		fr_mul(api, buf[7], buf[30]),
		fr_add(api,
			fr_mul(api,
				fr_add(api,
					fr_mul(api, buf[23], transcript[95]),
					fr_mul(api, buf[26], transcript[96]),
				),
				buf[9],
			),
			fr_add(api,
				fr_mul(api, buf[21], transcript[95]),
				fr_mul(api, buf[29], transcript[96]),
			),
		),
	)
	buf[25] = fr_mul(api,
		fr_mul(api, buf[20], buf[25]),
		buf[27],
	)
	buf[31] = fr_div(api,
		frOne,
		fr_add(api, buf[6], fr_neg(api, buf[24])),
		aux[17],
	)
	buf[32] = fr_mul(api, buf[23], buf[31])
	buf[34] = fr_div(api,
		frOne,
		fr_add(api, buf[19], fr_neg(api, buf[24])),
		aux[18],
	)
	buf[36] = fr_mul(api, buf[26], buf[34])
	buf[37] = fr_div(api,
		frOne,
		fr_add(api, buf[24], fr_neg(api, buf[6])),
		aux[19],
	)
	buf[38] = fr_div(api,
		frOne,
		fr_add(api, buf[24], fr_neg(api, buf[19])),
		aux[20],
	)
	buf[39] = fr_mul(api, buf[37], buf[38])
	buf[40] = fr_mul(api, buf[31], buf[24])
	buf[23] = fr_add(api,
		fr_mul(api, buf[21], buf[31]),
		fr_neg(api, fr_mul(api, buf[23], buf[40])),
	)
	buf[24] = fr_mul(api, buf[34], buf[24])
	buf[26] = fr_add(api,
		fr_mul(api, buf[29], buf[34]),
		fr_neg(api, fr_mul(api, buf[26], buf[24])),
	)
	buf[31] = fr_neg(api, fr_mul(api, buf[37], buf[6]))
	buf[19] = fr_mul(api, buf[38], buf[19])
	buf[34] = fr_add(api,
		fr_mul(api, buf[31], buf[38]),
		fr_neg(api, fr_mul(api, buf[37], buf[19])),
	)
	buf[37] = fr_add(api,
		fr_mul(api,
			fr_add(api,
				fr_add(api,
					fr_mul(api, buf[32], transcript[52]),
					fr_mul(api, buf[36], transcript[55]),
				),
				fr_mul(api, buf[39], transcript[57]),
			),
			buf[9],
		),
		fr_add(api,
			fr_add(api,
				fr_mul(api, buf[23], transcript[52]),
				fr_mul(api, buf[26], transcript[55]),
			),
			fr_mul(api, buf[34], transcript[57]),
		),
	)
	buf[21] = fr_neg(api, fr_mul(api, buf[21], buf[40]))
	buf[24] = fr_neg(api, fr_mul(api, buf[29], buf[24]))
	buf[19] = fr_neg(api, fr_mul(api, buf[31], buf[19]))
	buf[29] = fr_mul(api,
		buf[7],
		fr_add(api,
			fr_mul(api, buf[37], buf[9]),
			fr_add(api,
				fr_add(api,
					fr_mul(api, buf[21], transcript[52]),
					fr_mul(api, buf[24], transcript[55]),
				),
				fr_mul(api, buf[19], transcript[57]),
			),
		),
	)
	buf[23] = fr_add(api,
		fr_mul(api,
			fr_add(api,
				fr_add(api,
					fr_mul(api, buf[32], transcript[53]),
					fr_mul(api, buf[36], transcript[54]),
				),
				fr_mul(api, buf[39], transcript[56]),
			),
			buf[9],
		),
		fr_add(api,
			fr_add(api,
				fr_mul(api, buf[23], transcript[53]),
				fr_mul(api, buf[26], transcript[54]),
			),
			fr_mul(api, buf[34], transcript[56]),
		),
	)
	buf[19] = fr_add(api,
		buf[29],
		fr_add(api,
			fr_mul(api, buf[23], buf[9]),
			fr_add(api,
				fr_add(api,
					fr_mul(api, buf[21], transcript[53]),
					fr_mul(api, buf[24], transcript[54]),
				),
				fr_mul(api, buf[19], transcript[56]),
			),
		),
	)
	buf[20] = fr_mul(api, buf[20], buf[27])
	buf[18] = fr_add(api,
		fr_mul(api,
			buf[8],
			fr_add(api,
				fr_mul(api, buf[8], buf[18]),
				fr_mul(api, buf[30], buf[25]),
			),
		),
		fr_mul(api, buf[19], buf[20]),
	)

	constFr, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208581", 10)
	buf[12], buf[13] = frOne, constFr
	buf[14] = buf[18]
	err := ecc_mul(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[19] = fr_mul(api, buf[8], buf[8])
	buf[21] = fr_mul(api, buf[19], buf[33])
	buf[23] = fr_mul(api, buf[7], buf[7])
	buf[24] = fr_mul(api, buf[23], buf[23])
	buf[26] = fr_mul(api, buf[24], buf[24])
	buf[27] = fr_mul(api, buf[26], buf[26])
	buf[29] = fr_mul(api, buf[27], buf[26])
	buf[30] = fr_mul(api, buf[29], buf[24])
	buf[14], buf[15] = transcript[0], transcript[1]
	buf[16] = fr_mul(api, buf[21], buf[30])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[31] = fr_mul(api, buf[29], buf[23])
	buf[14], buf[15] = transcript[2], transcript[3]
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[31], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[14], buf[15] = transcript[4], transcript[5]
	buf[16] = fr_mul(api, buf[21], buf[31])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[14], buf[15] = transcript[6], transcript[7]
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[29], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[25] = fr_mul(api, buf[8], buf[25])
	buf[31] = fr_mul(api, buf[23], buf[7])
	buf[14], buf[15] = transcript[8], transcript[9]
	buf[16] = fr_mul(api, buf[25], buf[31])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[14], buf[15] = transcript[10], transcript[11]
	buf[16] = fr_mul(api, buf[21], buf[29])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[14], buf[15] = transcript[12], transcript[13]
	buf[16] = fr_mul(api, buf[20], buf[7])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[14], buf[15] = transcript[14], transcript[15]
	buf[16] = buf[20]
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[20] = fr_mul(api, buf[27], buf[23])

	constFr, _ = new(big.Int).SetString("8709125659475502415918518657557635300801773071942572628775212436421040063083", 10)
	constFr1, _ := new(big.Int).SetString("15004523228365939910023611806666411315026208567175240850752249087666257993887", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[20], buf[7]),
	)
	err = ecc_mul_add(api, buf[:][:], 12)
	if err != nil {
		return buf, err
	}

	constFr, _ = new(big.Int).SetString("2472483067641186468370720222926061505576985482694051633203803733348937658410", 10)
	constFr1, _ = new(big.Int).SetString("290727226204015910265829442784451419094608796265134826566269308064317977232", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api, buf[21], buf[20])
	err = ecc_mul_add(api, buf[:][:], 12)
	if err != nil {
		return buf, err
	}
	buf[20] = fr_mul(api, buf[26], buf[24])

	constFr, _ = new(big.Int).SetString("6806371257667040866528163341474533379006345124946545040399170085340008310799", 10)
	constFr1, _ = new(big.Int).SetString("12247874036535097401921174287325977216354185540896707277437125985797690340454", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api, buf[21], buf[20])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[29] = fr_mul(api, buf[26], buf[23])

	constFr, _ = new(big.Int).SetString("9621060932553241457331309181312468446375012848693562416915297961501104714797", 10)
	constFr1, _ = new(big.Int).SetString("18774224011527979955178720803820949077824414817387957068075380161701868796982", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[29], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}

	constFr, _ = new(big.Int).SetString("7332275780326935691999111227339181700750973508937555651107089016408829877447", 10)
	constFr1, _ = new(big.Int).SetString("10101962784746658718602667114782992736503033294933308373536577801383886245995", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api, buf[21], buf[29])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}

	constFr, _ = new(big.Int).SetString("11468226463687505935835900477341548496364145673428194470531622550606798549728", 10)
	constFr1, _ = new(big.Int).SetString("9837582624048510142004310301159632514776094018919612815235449315648081759843", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[27], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}

	constFr, _ = new(big.Int).SetString("10889266912826586897603159356170056230818131365470983959951001565597436237183", 10)
	constFr1, _ = new(big.Int).SetString("20874770016001072542025427943261199031240107769103237013265548919367111779466", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api, buf[21], buf[27])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[29] = fr_mul(api, buf[20], buf[23])

	constFr, _ = new(big.Int).SetString("7697388167245698493720664977599797506112018760356342935613685480468549855338", 10)
	constFr1, _ = new(big.Int).SetString("19073559406863410570432860804203668720108539750712213329299189076026146503769", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[29], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}

	constFr, _ = new(big.Int).SetString("20357685402742434514890462103117082206249083715998148179981579995731299942643", 10)
	constFr1, _ = new(big.Int).SetString("3796512760971928342650404431429604166427897244457277016482120559492192004594", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api, buf[21], buf[29])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}

	constFr, _ = new(big.Int).SetString("10745801118678109857576611554143128930522802852378059772094565113209157646297", 10)
	constFr1, _ = new(big.Int).SetString("19373196387014456806283620199938588386874600563947437192314074559888790715376", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[20], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[20] = fr_mul(api, buf[27], buf[24])

	constFr, _ = new(big.Int).SetString("11037694317603201060594459250660015500096248556089568488277250794362952833847", 10)
	constFr1, _ = new(big.Int).SetString("11250049497953170198433353686963067934430627870066853830340264005091259886722", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api, buf[21], buf[20])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}

	constFr, _ = new(big.Int).SetString("264243202592222827659227165388132108561735216681520405455526649693030169195", 10)
	constFr1, _ = new(big.Int).SetString("20144476218756846408362455241519320287339822741278545354972568833967557446223", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[20], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}

	constFr, _ = new(big.Int).SetString("5300213620446873398794261893907936515966120911215926896033101692577887886442", 10)
	constFr1, _ = new(big.Int).SetString("21207175973080685842000292459282738399800541246026953476688500608396927602776", 10)
	buf[14] = *constFr
	buf[15] = *constFr1
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[26], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[14], buf[15] = transcript[100], transcript[101]
	buf[16] = fr_neg(api,
		fr_mul(api,
			fr_mul(api,
				buf[17],
				fr_add(api,
					buf[9],
					fr_neg(api, buf[6]),
				),
			),
			buf[22],
		),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}

	buf[14], buf[15] = transcript[102], transcript[103]
	buf[16] = buf[9]
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}
	buf[17] = fr_mul(api, buf[21], buf[7])
	buf[14], buf[15] = transcript[42], transcript[43]
	buf[16] = fr_mul(api,
		buf[17],
		fr_mul(api, buf[35], buf[35]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return buf, err
	}

	return buf, nil
}
