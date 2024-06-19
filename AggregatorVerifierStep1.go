package main

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

func eccMul(api frontend.API, input []fr.Element, offset uint64) error {
	if input[offset+2] == fr.One() {
		return nil
	}

	res, err := CalcVerifyBN256Msm(api, input[offset:])
	if err != nil {
		return err
	}
	input[offset] = res[0]
	input[offset+1] = res[1]
	return nil
}

func verifyProof1(
	api frontend.API,
	transcript []fr.Element,
	aux []fr.Element,
	buf []fr.Element,
) []fr.Element {
	buf[10], buf[11] = transcript[102], transcript[103]
	buf[12] = fr.One()
	err := eccMul(api, buf, 10)
	if err != nil {
		panic(err)
	}
	constFr, _ := new(fr.Element).SetString("21710372849001950800533397158415938114909991150039389063546734567764856596059")
	buf[17] = fr_mul(
		*constFr,
		buf[6],
	)

	b := new(fr.Element).Add(&buf[17], new(fr.Element).Neg(&buf[6]))
	buf[18] = fr_div(
		fr.One(),
		*b,
		aux[0],
	)

	constFr, _ = new(fr.Element).SetString("8374374965308410102411073611984011876711565317741801500439755773472076597347")
	buf[19] = fr_mul(
		*constFr,
		buf[6],
	)
	b = new(fr.Element).Add(&buf[17], new(fr.Element).Neg(&buf[19]))
	buf[20] = fr_div(
		fr.One(),
		*b,
		aux[1],
	)

	buf[21] = fr_mul(buf[18], buf[20])
	b = new(fr.Element).Add(&buf[6], new(fr.Element).Neg(&buf[17]))
	buf[22] = fr_div(
		fr.One(),
		*b,
		aux[2],
	)

	b = new(fr.Element).Add(&buf[6], new(fr.Element).Neg(&buf[19]))
	buf[23] = fr_div(
		fr.One(),
		*b,
		aux[3],
	)
	buf[24] = fr_mul(buf[22], buf[23])

	b = new(fr.Element).Add(&buf[19], new(fr.Element).Neg(&buf[17]))
	buf[25] = fr_div(
		fr.One(),
		*b,
		aux[4],
	)

	b = new(fr.Element).Add(&buf[19], new(fr.Element).Neg(&buf[6]))
	buf[26] = fr_div(
		fr.One(),
		*b,
		aux[5],
	)
	buf[27] = fr_mul(buf[25], buf[26])

	tmp := fr_mul(buf[18], buf[6])
	buf[28] = *new(fr.Element).Neg(&tmp)
	buf[29] = fr_mul(buf[20], buf[19])

	tmp = fr_mul(buf[18], buf[29])
	buf[18] = fr_add(
		fr_mul(buf[28], buf[20]),
		*new(fr.Element).Neg(&tmp),
	)

	tmp = fr_mul(buf[22], buf[17])
	buf[20] = *new(fr.Element).Neg(&tmp)
	buf[30] = fr_mul(buf[23], buf[19])

	tmp = fr_mul(buf[22], buf[30])
	buf[22] = fr_add(
		fr_mul(buf[20], buf[23]),
		*new(fr.Element).Neg(&tmp),
	)

	tmp = fr_mul(buf[25], buf[17])
	buf[31] = *new(fr.Element).Neg(&tmp)
	buf[32] = fr_mul(buf[26], buf[6])

	tmp = fr_mul(buf[25], buf[30])
	buf[25] = fr_add(
		fr_mul(buf[31], buf[26]),
		*new(fr.Element).Neg(&tmp),
	)
	buf[33] = fr_add(
		fr_mul(
			fr_add(
				fr_add(
					fr_mul(buf[21], transcript[81]),
					fr_mul(buf[24], transcript[79]),
				),
				fr_mul(buf[27], transcript[80]),
			),
			buf[9],
		),
		fr_add(
			fr_add(
				fr_mul(buf[18], transcript[81]),
				fr_mul(buf[22], transcript[79]),
			),
			fr_mul(buf[25], transcript[80]),
		),
	)

	tmp = fr_mul(buf[28], buf[29])
	buf[28] = *new(fr.Element).Neg(&tmp)

	tmp = fr_mul(buf[20], buf[30])
	buf[20] = *new(fr.Element).Neg(&tmp)

	tmp = fr_mul(buf[31], buf[32])
	buf[29] = *new(fr.Element).Neg(&tmp)
	buf[31] = fr_mul(
		buf[7],
		fr_add(
			fr_mul(buf[33], buf[9]),
			fr_add(
				fr_add(
					fr_mul(buf[28], transcript[81]),
					fr_mul(buf[20], transcript[79]),
				),
				fr_mul(buf[29], transcript[80]),
			),
		),
	)

	buf[33] = fr_add(
		fr_mul(
			fr_add(
				fr_add(
					fr_mul(buf[21], transcript[84]),
					fr_mul(buf[24], transcript[82]),
				),
				fr_mul(buf[27], transcript[83]),
			),
			buf[9],
		),
		fr_add(
			fr_add(
				fr_mul(buf[18], transcript[84]),
				fr_mul(buf[22], transcript[82]),
			),
			fr_mul(buf[25], transcript[83]),
		),
	)
	buf[31] = fr_add(
		buf[31],
		fr_add(
			fr_mul(buf[33], buf[9]),
			fr_add(
				fr_add(
					fr_mul(buf[28], transcript[84]),
					fr_mul(buf[20], transcript[82]),
				),
				fr_mul(buf[29], transcript[83]),
			),
		),
	)
	buf[18] = fr_add(
		fr_mul(
			fr_add(
				fr_add(
					fr_mul(buf[21], transcript[87]),
					fr_mul(buf[24], transcript[85]),
				),
				fr_mul(buf[27], transcript[86]),
			),
			buf[9],
		),
		fr_add(
			fr_add(
				fr_mul(buf[18], transcript[87]),
				fr_mul(buf[22], transcript[85]),
			),
			fr_mul(buf[25], transcript[86]),
		),
	)
	buf[18] = fr_add(
		fr_mul(buf[7], buf[31]),
		fr_add(
			fr_mul(buf[18], buf[9]),
			fr_add(
				fr_add(
					fr_mul(buf[28], transcript[87]),
					fr_mul(buf[20], transcript[85]),
				),
				fr_mul(buf[29], transcript[86]),
			),
		),
	)

	constFr, _ = new(fr.Element).SetString("9741553891420464328295280489650144566903017206473301385034033384879943874347")
	buf[20] = fr_mul(
		*constFr,
		buf[6],
	)

	buf[21] = fr_div(
		fr.One(),
		fr_add(buf[20], *new(fr.Element).Neg(&buf[6])),
		aux[6],
	)
	buf[22] = fr_div(
		fr.One(),
		fr_add(buf[6], *new(fr.Element).Neg(&buf[20])),
		aux[7],
	)

	tmp = fr_mul(buf[21], buf[6])
	buf[24] = *new(fr.Element).Neg(&tmp)
	tmp = fr_mul(buf[22], buf[20])
	buf[25] = *new(fr.Element).Neg(&tmp)
	buf[27] = fr_mul(
		buf[7],
		fr_add(
			fr_mul(
				fr_add(
					fr_mul(buf[21], transcript[93]),
					fr_mul(buf[22], transcript[92]),
				),
				buf[9],
			),
			fr_add(
				fr_mul(buf[24], transcript[93]),
				fr_mul(buf[25], transcript[92]),
			),
		),
	)
	buf[21] = fr_add(
		buf[27],
		fr_add(
			fr_mul(
				fr_add(
					fr_mul(buf[21], transcript[98]),
					fr_mul(buf[22], transcript[97]),
				),
				buf[9],
			),
			fr_add(
				fr_mul(buf[24], transcript[98]),
				fr_mul(buf[25], transcript[97]),
			),
		),
	)

	tmp = *new(fr.Element).Neg(&buf[17])
	buf[17] = fr_add(
		buf[9],
		tmp,
	)
	tmp = *new(fr.Element).Neg(&buf[19])
	buf[22] = fr_add(
		buf[9],
		tmp,
	)

	constFr, _ = new(fr.Element).SetString("11211301017135681023579411905410872569206244553457844956874280139879520583390")
	buf[24] = fr_mul(
		*constFr,
		buf[6],
	)

	tmp = *new(fr.Element).Neg(&buf[24])
	buf[25] = fr_add(
		buf[9],
		tmp,
	)

	tmp = *new(fr.Element).Neg(&buf[20])
	buf[20] = fr_add(
		buf[9],
		tmp,
	)
	buf[27] = fr_div(
		fr.One(),
		fr_mul(buf[20], buf[25]),
		aux[8],
	)
	buf[28] = fr_mul(
		fr_mul(
			fr_mul(buf[17], buf[22]),
			buf[25],
		),
		buf[27],
	)
	buf[29] = fr_mul(
		buf[7],
		fr_add(
			fr_mul(
				buf[7],
				fr_add(
					fr_mul(buf[7], transcript[44]),
					transcript[45],
				),
			),
			transcript[46],
		),
	)
	buf[29] = fr_add(
		fr_mul(
			buf[7],
			fr_add(
				fr_mul(
					buf[7],
					fr_add(buf[29], transcript[47]),
				),
				transcript[48],
			),
		),
		transcript[51],
	)
	buf[29] = fr_mul(
		buf[7],
		fr_add(
			fr_mul(
				buf[7],
				fr_add(
					fr_mul(buf[7], buf[29]),
					transcript[94],
				),
			),
			transcript[99],
		),
	)
	buf[29] = fr_add(
		fr_mul(
			buf[7],
			fr_add(
				fr_mul(
					buf[7],
					fr_add(buf[29], transcript[58]),
				),
				transcript[59],
			),
		),
		transcript[60],
	)
	buf[29] = fr_mul(
		buf[7],
		fr_add(
			fr_mul(
				buf[7],
				fr_add(
					fr_mul(buf[7], buf[29]),
					transcript[61],
				),
			),
			transcript[62],
		),
	)
	buf[29] = fr_add(
		fr_mul(
			buf[7],
			fr_add(
				fr_mul(
					buf[7],
					fr_add(buf[29], transcript[63]),
				),
				transcript[64],
			),
		),
		transcript[65],
	)
	buf[29] = fr_mul(
		buf[7],
		fr_add(
			fr_mul(
				buf[7],
				fr_add(
					fr_mul(buf[7], buf[29]),
					transcript[66],
				),
			),
			transcript[67],
		),
	)
	buf[29] = fr_add(
		fr_mul(
			buf[7],
			fr_add(
				fr_mul(
					buf[7],
					fr_add(buf[29], transcript[68]),
				),
				transcript[69],
			),
		),
		transcript[70],
	)
	buf[29] = fr_mul(
		buf[7],
		fr_add(
			fr_mul(
				buf[7],
				fr_add(
					fr_mul(buf[7], buf[29]),
					transcript[72],
				),
			),
			transcript[73],
		),
	)
	buf[29] = fr_add(
		fr_mul(
			buf[7],
			fr_add(
				fr_mul(
					buf[7],
					fr_add(buf[29], transcript[74]),
				),
				transcript[75],
			),
		),
		transcript[76],
	)
	buf[29] = fr_mul(
		buf[7],
		fr_add(
			fr_mul(
				buf[7],
				fr_add(
					fr_mul(buf[7], buf[29]),
					transcript[77],
				),
			),
			transcript[78],
		),
	)
	buf[31] = fr_add(
		fr_add(
			fr_add(
				fr_add(
					transcript[58],
					fr_mul(
						transcript[50],
						transcript[59],
					),
				),
				fr_mul(transcript[45], transcript[60]),
			),
			fr_mul(transcript[46], transcript[61]),
		),
		fr_mul(transcript[47], transcript[62]),
	)
	buf[31] = fr_add(
		fr_add(
			fr_add(
				fr_add(
					buf[31],
					fr_mul(
						transcript[48],
						transcript[63],
					),
				),
				fr_mul(transcript[49], transcript[64]),
			),
			fr_mul(
				fr_mul(transcript[45], transcript[46]),
				transcript[65],
			),
		),
		fr_mul(
			fr_mul(transcript[47], transcript[48]),
			transcript[66],
		),
	)

	constFr, _ = new(fr.Element).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495615")
	buf[33] = fr_add(
		transcript[70],
		*constFr,
	)
	constFr, _ = new(fr.Element).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495614")
	buf[34] = fr_add(
		transcript[70],
		*constFr,
	)

	tmp = *new(fr.Element).Neg(&transcript[52])
	buf[35] = fr_mul(
		fr_mul(
			fr_mul(
				fr_add(
					transcript[51],
					tmp,
				),
				transcript[70],
			),
			buf[33],
		),
		buf[34],
	)

	tmp = *new(fr.Element).Neg(&transcript[53])
	product := fr_mul(transcript[54], *new(fr.Element).SetUint64(262144))
	tmp1 := *new(fr.Element).Neg(&product)
	buf[36] = fr_add(
		fr_add(
			transcript[51],
			tmp,
		),
		tmp1,
	)

	buf[37] = fr_mul(
		fr_add(
			fr_add(
				buf[36],
				-fr_mul(
					transcript[52],
					68719476736,
				),
			),
			-fr_mul(
				transcript[55],
				18014398509481984,
			),
		),
		transcript[70],
	)
	buf[38] = fr_add(
		transcript[70],
		21888242871839275222246405745257275088548364400416034343698204186575808495616,
	)
	buf[31] = fr_mul(
		fr_add(
			fr_mul(
				fr_add(
					fr_mul(buf[31], buf[5]),
					buf[35],
				),
				buf[5],
			),
			fr_mul(
				fr_mul(buf[37], buf[38]),
				buf[34],
			),
		),
		buf[5],
	)
	buf[34] = fr_add(
		fr_add(
			fr_add(
				buf[36],
				-fr_mul(
					transcript[56],
					68719476736,
				),
			),
			-fr_mul(
				transcript[52],
				18014398509481984,
			),
		),
		-fr_mul(
			transcript[55],
			4722366482869645213696,
		),
	)
	buf[34] = fr_mul(
		fr_mul(
			fr_add(
				buf[34],
				-fr_mul(
					transcript[57],
					1237940039285380274899124224,
				),
			),
			transcript[70],
		),
		buf[38],
	)
	buf[35] = fr_pow(buf[6], 8388608)
	buf[36] = fr_add(buf[35] - 1)
	buf[37] = fr_div(
		fr_mul(
			21888240262557392955334514970720457388010314637169927192662615958087340972065,
			buf[36],
		),
		fr_add(buf[6]-1),
		aux[9],
	)
	buf[31] = fr_mul(
		fr_add(
			fr_mul(
				fr_add(
					buf[31],
					fr_mul(buf[34], buf[33]),
				),
				buf[5],
			),
			fr_mul(
				buf[37],
				fr_add(
					1,
					-transcript[79],
				),
			),
		),
		buf[5],
	)
	buf[33] = fr_div(
		fr_mul(
			4976187549286291281196346419790865785215437125361463174887299780224677482739,
			buf[36],
		),
		fr_add(
			buf[6],
			-21710372849001950800533397158415938114909991150039389063546734567764856596059,
		),
		aux[10],
	)
	buf[31] = fr_mul(
		fr_add(
			buf[31],
			fr_mul(
				buf[33],
				fr_add(
					fr_mul(
						transcript[88],
						transcript[88],
					),
					-transcript[88],
				),
			),
		),
		buf[5],
	)
	buf[31] = fr_add(
		fr_mul(
			fr_add(
				buf[31],
				fr_mul(
					fr_add(
						transcript[82],
						-transcript[81],
					),
					buf[37],
				),
			),
			buf[5],
		),
		fr_mul(
			fr_add(
				transcript[85],
				-transcript[84],
			),
			buf[37],
		),
	)
	buf[34] = fr_add(transcript[46], buf[4])
	buf[38] = fr_add(transcript[45], buf[4])
	buf[39] = fr_mul(buf[3], buf[6])
	buf[34] = fr_add(
		fr_mul(
			fr_add(
				buf[34],
				fr_mul(buf[3], transcript[73]),
			),
			fr_mul(
				fr_add(
					buf[38],
					fr_mul(buf[3], transcript[72]),
				),
				transcript[80],
			),
		),
		-fr_mul(
			fr_add(
				buf[34],
				fr_mul(
					4131629893567559867359510883348571134090853742863529169391034518566172092834,
					buf[39],
				),
			),
			fr_mul(
				fr_add(buf[38], buf[39]),
				transcript[79],
			),
		),
	)
	//buf[38] = fr_add(
	//fr_add(
	//fr_add(
	//fr_div(
	//fr_mul(
	//17545179510056424625657753961500172777187948487824275719647175633757629801999,
	//buf[36],
	//
	//),
	//fr_add(
	//buf[6],
	// -
	//1887003188133998471169152042388914354640772748308168868301418279904560637395,
	//
	//),
	//aux[11]
	//),
	//fr_div(
	//fr_mul(
	//12181902470161097505840471953356915228510866946798053228669051859673065660797,
	//buf[36],
	//
	//),
	//fr_add(
	//buf[6],
	// -
	//2785514556381676080176937710880804108647911392478702105860685610379369825016,
	//
	//),
	//aux[12]
	//),
	//
	//),
	//fr_div(
	//fr_mul(
	//3094683119308499972127188652296432785995218440930254516456812473854441617488,
	//buf[36],
	//
	//),
	//fr_add(
	//buf[6],
	// -
	//14655294445420895451632927078981340937842238432098198055057679026789553137428,
	//
	//),
	//aux[13]
	//),
	//
	//),
	//fr_div(
	//fr_mul(
	//17403859010271654340651602860211012227656903909453797585120745724534928821531,
	//buf[36],
	//
	//),
	//fr_add(
	//buf[6],
	// -
	//8734126352828345679573237859165904705806588461301144420590422589042130041188,
	//
	//),
	//aux[14]
	//),
	//
	//);
	//buf[38] = fr_add(
	//1,
	// -
	//fr_add(
	//buf[33],
	//fr_add(
	//buf[38],
	//fr_div(
	//fr_mul(
	//7444483286096152693477325065105185543054922671492455540957072536952082259082,
	//buf[36],
	//
	//),
	//fr_add(
	//buf[6],
	// -
	//9741553891420464328295280489650144566903017206473301385034033384879943874347,
	//
	//),
	//aux[15]
	//),
	//
	//),
	//
	//),
	//
	//);
	//buf[31] = fr_add(
	//fr_mul(
	//fr_add(
	//fr_mul(buf[31], buf[5]),
	//fr_mul(
	//fr_add(
	//transcript[88],
	// - transcript[87],
	//
	//),
	//buf[37],
	//
	//),
	//
	//),
	//buf[5],
	//
	//),
	//fr_mul(buf[34], buf[38]),
	//
	//);
	//buf[34] = fr_add(transcript[48], buf[4]);
	//buf[40] = fr_add(transcript[47], buf[4]);
	//buf[41] = fr_pow(
	//4131629893567559867359510883348571134090853742863529169391034518566172092834,
	//2
	//);
	//buf[41] = fr_mul(buf[39], buf[41]);
	//buf[34] = fr_add(
	//fr_mul(
	//fr_add(
	//buf[34],
	//fr_mul(buf[3], transcript[75]),
	//
	//),
	//fr_mul(
	//fr_add(
	//buf[40],
	//fr_mul(buf[3], transcript[74]),
	//
	//),
	//transcript[83],
	//
	//),
	//
	//),
	// -
	//fr_mul(
	//fr_add(
	//buf[34],
	//fr_mul(
	//4131629893567559867359510883348571134090853742863529169391034518566172092834,
	//buf[41],
	//
	//),
	//
	//),
	//fr_mul(
	//fr_add(buf[40], buf[41]),
	//transcript[82],
	//
	//),
	//
	//),
	//
	//);
	//buf[40] = fr_add(transcript[51], buf[4]);
	//buf[41] = fr_add(transcript[49], buf[4]);
	//buf[42] = fr_pow(
	//4131629893567559867359510883348571134090853742863529169391034518566172092834,
	//4
	//);
	//buf[42] = fr_mul(buf[39], buf[42]);
	//buf[40] = fr_add(
	//fr_mul(
	//fr_add(
	//buf[40],
	//fr_mul(buf[3], transcript[77]),
	//
	//),
	//fr_mul(
	//fr_add(
	//buf[41],
	//fr_mul(buf[3], transcript[76]),
	//
	//),
	//transcript[86],
	//
	//),
	//
	//),
	// -
	//fr_mul(
	//fr_add(
	//buf[40],
	//fr_mul(
	//4131629893567559867359510883348571134090853742863529169391034518566172092834,
	//buf[42],
	//
	//),
	//
	//),
	//fr_mul(
	//fr_add(buf[41], buf[42]),
	//transcript[85],
	//
	//),
	//
	//),
	//
	//);
	//buf[31] = fr_mul(
	//fr_add(
	//fr_mul(
	//fr_add(
	//fr_mul(buf[31], buf[5]),
	//fr_mul(buf[34], buf[38]),
	//
	//),
	//buf[5],
	//
	//),
	//fr_mul(buf[40], buf[38]),
	//
	//),
	//buf[5],
	//
	//);
	//buf[34] = fr_add(transcript[44], buf[4]);
	//buf[40] = fr_pow(
	//4131629893567559867359510883348571134090853742863529169391034518566172092834,
	//6
	//);
	//buf[34] = fr_mul(
	//fr_add(
	//fr_mul(
	//fr_add(
	//buf[34],
	//fr_mul(buf[3], transcript[78]),
	//
	//),
	//transcript[89],
	//
	//),
	// -
	//fr_mul(
	//fr_add(
	//buf[34],
	//fr_mul(buf[39], buf[40]),
	//
	//),
	//transcript[88],
	//
	//),
	//
	//),
	//buf[38],
	//
	//);
	//buf[31] = fr_add(
	//fr_mul(
	//fr_add(
	//fr_mul(
	//fr_add(buf[31], buf[34]),
	//buf[5],
	//
	//),
	//fr_mul(
	//buf[37],
	//fr_add(
	//1,
	// - transcript[90],
	//
	//),
	//
	//),
	//
	//),
	//buf[5],
	//
	//),
	//fr_mul(
	//buf[33],
	//fr_add(
	//fr_mul(transcript[90], transcript[90]),
	// - transcript[90],
	//
	//),
	//
	//),
	//
	//);
	//buf[34] = fr_add(
	//fr_add(
	//fr_mul(transcript[68], buf[2]),
	//transcript[69],
	//
	//),
	//buf[4],
	//
	//);
	//buf[39] = fr_mul(
	//fr_mul(
	//transcript[90],
	//fr_add(
	//fr_add(
	//fr_mul(transcript[67], buf[2]),
	//transcript[52],
	//
	//),
	//buf[3],
	//
	//),
	//
	//),
	//buf[34],
	//
	//);

	return buf
}
