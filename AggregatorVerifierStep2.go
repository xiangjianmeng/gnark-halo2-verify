package main

import (
	"github.com/consensys/gnark/frontend"
)

func VerifyProof2(
	api frontend.API,
	transcript []frontend.Variable,
	aux []frontend.Variable,
	buf [43]frontend.Variable,
) ([43]frontend.Variable, error) {
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
						1,
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
	buf[33] = fr_mul(api,
		fr_mul(api,
			transcript[95],
			fr_add(api,
				fr_add(api,
					fr_mul(api, 18, buf[2]),
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
		1,
		fr_add(api, buf[6], fr_neg(api, buf[24])),
		aux[17],
	)
	buf[32] = fr_mul(api, buf[23], buf[31])
	buf[34] = fr_div(api,
		1,
		fr_add(api, buf[19], fr_neg(api, buf[24])),
		aux[18],
	)
	buf[36] = fr_mul(api, buf[26], buf[34])
	buf[37] = fr_div(api,
		1,
		fr_add(api, buf[24], fr_neg(api, buf[6])),
		aux[19],
	)
	buf[38] = fr_div(api,
		1,
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
	buf[12], buf[13] = fr_from_string("1"), fr_from_string("21888242871839275222246405745257275088696311157297823662689037894645226208581")
	buf[14] = buf[18]
	err := ecc_mul(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
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
		return [43]frontend.Variable{}, err
	}
	buf[31] = fr_mul(api, buf[29], buf[23])
	buf[14], buf[15] = transcript[2], transcript[3]
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[31], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[4], transcript[5]
	buf[16] = fr_mul(api, buf[21], buf[31])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[6], transcript[7]
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[29], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[25] = fr_mul(api, buf[8], buf[25])
	buf[31] = fr_mul(api, buf[23], buf[7])
	buf[14], buf[15] = transcript[8], transcript[9]
	buf[16] = fr_mul(api, buf[25], buf[31])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[10], transcript[11]
	buf[16] = fr_mul(api, buf[21], buf[29])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[12], transcript[13]
	buf[16] = fr_mul(api, buf[20], buf[7])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[14], transcript[15]
	buf[16] = buf[20]
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[20] = fr_mul(api, buf[27], buf[23])
	buf[14], buf[15] = fr_from_string("7302810833326292183657845455542786945088085612690237136517265240120492143686"), fr_from_string("12265020872042776853325862543934338413628778238311540007481750568301839403357")
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[20], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = fr_from_string("15714457855017303792793529634633875645702708944223275612000098593544931343989"), fr_from_string("15257349176403661815620892222123615612513039066905856829097618251943836626674")
	buf[16] = fr_mul(api, buf[21], buf[20])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[20] = fr_mul(api, buf[26], buf[24])
	buf[14], buf[15] = fr_from_string("15488644080723619432119612346004359086916581306660788742559926675716559909239"), fr_from_string("8754616038193501373921013994731307318251353370144049595366428636287857472101")
	buf[16] = fr_mul(api, buf[21], buf[20])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[29] = fr_mul(api, buf[26], buf[23])
	buf[14], buf[15] = fr_from_string("9621060932553241457331309181312468446375012848693562416915297961501104714797"), fr_from_string("18774224011527979955178720803820949077824414817387957068075380161701868796982")
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[29], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = fr_from_string("7332275780326935691999111227339181700750973508937555651107089016408829877447"), fr_from_string("10101962784746658718602667114782992736503033294933308373536577801383886245995")
	buf[16] = fr_mul(api, buf[21], buf[29])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = fr_from_string("6588502116763777047662055789514359601800459134197048587585162560883404012798"), fr_from_string("11714447983073049655392713639630119352182916653299642193786804830268642535746")
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[27], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = fr_from_string("9125246457194062079192598275178850075343678690105278369118112655547944406336"), fr_from_string("294075161521838319967190643963225379772318561607769296285010787743709643736")
	buf[16] = fr_mul(api, buf[21], buf[27])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[29] = fr_mul(api, buf[20], buf[23])
	buf[14], buf[15] = fr_from_string("21619461572256759847460179508152708219554585855297084173283796582786124555803"), fr_from_string("4345524860916738024637605707697977254152854672257192099656709386158566955621")
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[29], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = fr_from_string("17258678549324502889708499924818360135272319280666991023610380123832805047961"), fr_from_string("5334989116053542497869652553010890811115308152577125353854023583257775982812")
	buf[16] = fr_mul(api, buf[21], buf[29])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = fr_from_string("5308159394739710035241344480420553410175387652800783904684585252715061491340"), fr_from_string("3019131547261358901530790449779825851153791728474681515444029058543922522335")
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[20], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[20] = fr_mul(api, buf[27], buf[24])
	buf[14], buf[15] = fr_from_string("1602442613231540506062434465510844080484629772386483161935289973450738328411"), fr_from_string("8632200768118172237953570969696965645934378330803102067059028669153881824687")
	buf[16] = fr_mul(api, buf[21], buf[20])
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = fr_from_string("14938380413158645463746726818663993049411440720262319458512240364576743949172"), fr_from_string("612698444000497655149316219443956538920213548045757527589465098726453410217")
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[20], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = fr_from_string("18180235640340843615912844522870848024440129915340282133294923228193557588624"), fr_from_string("16150223963193906991297402627411591966306440109235686551266596870812093013098")
	buf[16] = fr_mul(api,
		buf[21],
		fr_mul(api, buf[26], buf[7]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
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
		return [43]frontend.Variable{}, err
	}
	buf[14], buf[15] = transcript[102], transcript[103]
	buf[16] = buf[9]
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}
	buf[17] = fr_mul(api, buf[21], buf[7])
	buf[14], buf[15] = transcript[42], transcript[43]
	buf[16] = fr_mul(api,
		buf[17],
		fr_mul(api, buf[35], buf[35]),
	)
	err = ecc_mul_add(api, buf[:], 12)
	if err != nil {
		return [43]frontend.Variable{}, err
	}

	return buf, nil
}
