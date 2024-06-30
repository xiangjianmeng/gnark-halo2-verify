package main

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"log"
	"math/big"
	"testing"

	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/bn256"
)

func TestMsmSolve(t *testing.T) {
	assert := test.NewAssert(t)
	x, _ := new(big.Int).SetString("1", 10)
	y, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208581", 10)
	scalar, _ := new(big.Int).SetString("21147276235438245106538451154094232271190030085887596632745409482267565260819", 10)

	var blob []byte
	blob = append(blob, x.FillBytes(make([]byte, 32))...)
	blob = append(blob, y.FillBytes(make([]byte, 32))...)

	p := new(bn256.G1)
	_, err := p.Unmarshal(blob)
	assert.NoError(err)

	log.Println("TestMsmSolve", p.String())

	res := new(bn256.G1)
	res.ScalarMult(p, scalar)

	xStr, yStr, _ := extractAndConvert(res.String())

	log.Println("TestMsmSolve", xStr, yStr)

	var resCircuit = bn254.G1Affine{}
	_, err = resCircuit.X.SetString(xStr)
	assert.NoError(err)
	_, err = resCircuit.Y.SetString(yStr)
	assert.NoError(err)
	assert.True(resCircuit.IsOnCurve())

	witnessCircuit := BN254ScalarMul{
		Point:  [2]frontend.Variable{x, y},
		Scalar: frontend.Variable(scalar),
		Res:    [2]frontend.Variable{resCircuit.X.BigInt(new(big.Int)), resCircuit.Y.BigInt(new(big.Int))},
	}
	circuit := BN254ScalarMul{
		Point:  [2]frontend.Variable{},
		Scalar: frontend.Variable(scalar),
		Res:    [2]frontend.Variable{},
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Failed to compile circuit: %v", err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("Failed to setup keys: %v", err)
	}

	witness, err := frontend.NewWitness(&witnessCircuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to create proof: %v", err)
	}

	public, err := witness.Public()
	if err != nil {
		log.Fatalf("Failed to Public: %v", err)
	}

	if err := groth16.Verify(proof, vk, public); err != nil {
		log.Fatalf("Failed to verify proof: %v", err)
	}

	//err = test.IsSolved(&circuit, &witnessCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestSha2Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	input, succ := new(big.Int).SetString("21018549926786911420919261871844456760738199621624594828144407595472474813958", 10)
	assert.True(succ)

	inputBytes := input.FillBytes(make([]byte, 32))
	ethHashVal := sha256.Sum256(inputBytes)
	//keccakHashVal := crypto.Keccak256Hash(inputBytes)
	//log.Println(ethHashVal, keccakHashVal.Bytes())

	inputCircuit := uints.NewU8Array(inputBytes)
	hashValCircuit := uints.NewU8Array(ethHashVal[:])
	log.Println(inputCircuit)
	log.Println(hashValCircuit)
	witnessCircuit := Sha256Circuit{
		inputCircuit,
		hashValCircuit,
	}
	circuit := Sha256Circuit{
		InputValue: make([]uints.U8, len(inputBytes)),
		HashValue:  make([]uints.U8, len(ethHashVal[:])),
	}

	err := test.IsSolved(&circuit, &witnessCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestKeccak256Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	input, succ := new(big.Int).SetString("21018549926786911420919261871844456760738199621624594828144407595472474813958", 10)
	assert.True(succ)

	inputBytes := input.FillBytes(make([]byte, 32))
	keccakHashVal := crypto.Keccak256Hash(inputBytes)
	//log.Println(inputBytes)
	//log.Println(keccakHashVal.Bytes())

	inputCircuit := uints.NewU8Array(inputBytes)
	hashValCircuit := uints.NewU8Array(keccakHashVal.Bytes())
	//log.Println(inputCircuit)
	//log.Println(hashValCircuit)
	witnessCircuit := Keccak256Circuit{
		inputCircuit,
		hashValCircuit,
	}
	circuit := Keccak256Circuit{
		InputValue: make([]uints.U8, len(inputBytes)),
		HashValue:  make([]uints.U8, len(keccakHashVal.Bytes())),
	}

	err := test.IsSolved(&circuit, &witnessCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestCheckOnCurveCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	//x, _ := new(big.Int).SetString("1", 10)
	//y, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208581", 10)
	x, _ := new(big.Int).SetString("16773608191221444274034723634505800152348638783233618286564858032846349483658", 10)
	y, _ := new(big.Int).SetString("5309254838970461055039540544217759521764333506680767687704942616109839409613", 10)

	witnessCircuit := CheckOnCurveCircuit{
		x,
		y,
	}
	//circuit := CheckOnCurveCircuit{}

	//_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &witnessCircuit)
	//if err != nil {
	//	panic(err)
	//}

	err := test.IsSolved(&witnessCircuit, &witnessCircuit, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestBigMod(t *testing.T) {
	b, _ := new(big.Int).SetString("7264406879962038625787264009404137460377457101078411404048363683262191883717", 10)
	aux, _ := new(big.Int).SetString("14682075548635262302074385051110702234086274396931195933546742286128764358125", 10)

	product := b.Mul(b, aux)

	log.Println(product.String())

	log.Println(product.Mod(product, MODULUS).String())
}

func TestHexToBase(t *testing.T) {
	bufStr := []string{
		"14518669122153204107438001167275775392293121025028421520190945678452919453116",
		"17093993445643899230068359428052269750701581214259397668825355106622530890359",
		"11998403060490390570455295813295651267749063915313021105374173689081403863257",
		"2495735567390302507201888405163469563532488217546814052976483435583288670565",
		"14059003638501981466784405033930231791072560930660624891412078762767896781609",
		"9618638276073043292923148356967627316354531496479286038747655855210260248763",
		"7264406879962038625787264009404137460377457101078411404048363683262191883717",
		"11388297455859133038480661962794609878975270610033719337414430187627923593514",
		"5407378722455163557827638766233330495102514713373201611482560475011947871717",
		"10696824190703641741008737755241846718268731271095825424278589440469985414304",
	}

	buf := make([]*big.Int, len(proofStr))
	for i := 0; i < len(bufStr); i++ {
		buf[i], _ = new(big.Int).SetString(bufStr[i], 10)
		log.Println(buf[i].String())
	}
}

func TestSqueezeChallenge(t *testing.T) {
	//bufStr := []string{
	//	"14518669122153204107438001167275775392293121025028421520190945678452919453116",
	//	"17093993445643899230068359428052269750701581214259397668825355106622530890359",
	//	"11998403060490390570455295813295651267749063915313021105374173689081403863257",
	//	"2495735567390302507201888405163469563532488217546814052976483435583288670565",
	//	"14059003638501981466784405033930231791072560930660624891412078762767896781609",
	//	"9618638276073043292923148356967627316354531496479286038747655855210260248763",
	//	"7264406879962038625787264009404137460377457101078411404048363683262191883717",
	//	"11388297455859133038480661962794609878975270610033719337414430187627923593514",
	//	"5407378722455163557827638766233330495102514713373201611482560475011947871717",
	//	"10696824190703641741008737755241846718268731271095825424278589440469985414304",
	//}

	//bufStr := []string{
	//	"00000000000000000000000000000000000000000000000061f96cb6aff57754",
	//	"000000000000000000000000000000000000000000000000237b2cbd779f0d98",
	//	"2e7813e2ab7095204c7efba4fbe356d60b3064b86c1b1ef234edd4eebcab3606",
	//	"0000000000000000000000000000000000000000000000007c8b5f18e9bf5443",
	//	"1760673487281a87933156f40a53a46969cc882c0ed465f69cc380001ba0e26a",
	//	"0000000000000000000000000000000000000000000000000000000000000000",
	//	"0000000000000000000000000000000000000000000000000000000000000000",
	//	"0000000000000000000000000000000000000000000000000000000000000000",
	//	"0000000000000000000000000000000000000000000000000000000000000000",
	//	"0000000000000000000000000000000000000000000000000000000000000000",
	//}

	//bufStr := []string{
	//	"2920616387084030925907755037226454382846345550621956833249622258647667607078",
	//	"16502678157049327323910877548707266122319935523346850792311342099791838736912",
	//	"12573005921276352472929923238615004089566478023566067316598208128132732745355",
	//	"12024405228272103929747566698126288604391444364896006494111292076262270732980",
	//	"2920616387084030925907755037226454382846345550621956833249622258647667607078",
	//	"16502678157049327323910877548707266122319935523346850792311342099791838736912",
	//	"7162082828732168937516361335135022403650719329242056518668518043784043198510",
	//	"18768486256042060147567165227366772940689098806912976766549486364846889365307",
	//}

	bufStr := []string{
		"2019468813ad3bfb184eec100a4f586a75635286fb97ea624ea0372ab83945bc",
		"25cadb8048af8478880564973a1a470beae2842392885eb4fa8ae853bd1baa77",
		"1a86db004dd17617b5a369186c5f99a4fb1860bd75f46fa5d84764ea1728f0d9",
		"058489492ba829c0486d2b820fa6f4e05bd1718523f1f89a476d0c1669747965",
		"1f151d33af47710bb034c64f468ba9df39758425243168a7693d3c3c3dd3a329",
		"1543f4d28c68ea41ab4ea9aeab56579fcbbb91b033eb3a616ae52f993232b8bb",
		"100f8232cd716f876ec209e5b0e8eab6d5b81abca006ac0c614934d827f3d5c5",
		"192d8c45b0f96f98dbd4b1a88ca556d5b59bab53f4272668dbb3ae4aa87f592a",
		"0bf477c82a0d9682ded1db91c8c79a2513e65b822c9fe20a2b2b4742fbcabde5",
		"17a6301ccf4f0489b01c156674f117b7c5c4f83cd439ed10aa9b5c7a36504ca0",

		"067502a2aaeec1739d0be3c677e8a16d245e14daf50f461c9ec15d4c2f888626",
		"247c2f513abb7b5cab4144f87540d2020f4807097a90d7935b2f76b4b5c47210",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"118e5a1c1a722142cb7e3e03ada5291596942a24416871753f75c40d5c578503",
		"2bd0e4da8ae31ad34625a1213f3649800cd3c8b1fd45f7e118b8d78de216cda1",
		"0855a3bb64c10f81cfbc6fbf178e020044367e230eaf63ad34ca6db254f9d44c",

		"11f5fca8371622c457e9d32094ea4b37518cd6748b9f0303e9abf540eac9356b",
		"06c5ac199ce325840c4469f3a546c262e2ccde85d9d7769b4117058013f0826b",
		"0f508c616a8df507e05fa5a75d6315b7818e7a19c58a896375d0eec7e1567854",
		"2875d8037c7fd58fb33017cb914606dd3b68493188c8a12e0ee703563fd4fdb9",
		"2e24d289bfafbf1d80fcb9f3ca0273f73fa85cb027e8ce388d7485b97c90001b",
		"19e5ac05f0d0e595e76fa1292c6ffc1dae5083d5260a8f696108cc54a9c04c86",
		"07ee766f64b1ca9a05202deaf03b517feccb9f16f0f0cf6334faf23db02b0248",
		"0323555c1c4305b817585ba76acea2e6ef00369d47cbc79b87cb5abf1a798728",
		"060ceadb8825f9607efb8e4918d829a604071d2d201e2068b869ab7d54c0babd",
		"028dbd6f17f75e54f1d2a5825a6288111d10962ddb36b797b25809f797de6d16",

		"1346172434cec1d0c63ea4569760658da97c1f16e0869539c56446c05065a1a0",
		"2eb660de0b8f9c4116f7f553debfea73bdcb8bb0c25cd9e01e7f97c081ead0c1",
		"1d1e374eac62de58f211a15fea20f2cf7eb7c9319932db577e7daed39f9a5e60",
		"19d81360c6f32f42761360fb6003c29eab451435f15d6b7cd7f4a5788ac97861",
		"22a0d08de4170dd415dfb8270f03ea416955b976ebf259ac2591f7151116a6aa",
		"1ded2b235ff4e7353a5698f7a0a59ec15372b5523c5be63ca303edc944b1b1cf",
		"1ded2b235ff4e7353a5698f7a0a59ec15372b5523c5be63ca303edc944b1b1ce",
		"0c9e7892f3706a46e6ae915abf41499be6f8bb862a698d584d6961d4765c836f",
		"2f91ee2fd91f552f0c01048482b3c082a84e355525d1dc5f8951e6ffde9611e3",
		"279c91b03ba32131225b2c8dffaa0a14c4993b030579f262f5e61227a16a9af8",

		"0c700e936f498cfaff7ab722787c51d54dbe76b8dbb8e572533863af6c71421b",
		"0e21eca359dbb9af5dce7ea85c0d28d4d02dc1810537e6c2ff7abb6247f394cd",
		"160358d426c794afa49b046600102e357de5e73e1bbe7ce217baeb8a48123c88",
		"160358d426c794afa49b046600102e357de5e73e1bbe7ce217baeb8a48123c88",
	}

	//buf := make([]*big.Int, len(proofStr))
	//for i := 0; i < len(bufStr); i++ {
	//	buf[i], _ = new(big.Int).SetString(bufStr[i], 16)
	//	log.Println(buf[i].String())
	//}

	var inputBytes []byte
	for i := 0; i < len(bufStr); i++ {
		res, _ := new(big.Int).SetString(bufStr[i], 16)
		log.Println(res.String())
		inputBytes = append(inputBytes, res.FillBytes(make([]byte, 32))...)
	}
	//inputBytes = append(inputBytes, 0x0)
	//ethHashVal := sha256.Sum256(inputBytes)
	//ethHashBig := new(big.Int).SetBytes(ethHashVal[:])
	//log.Println(ethHashBig.Mod(ethHashBig, MODULUS))
}

func TestMod(t *testing.T) {
	x, _ := new(big.Int).SetString("21147276235438245106538451154094232271190030085887596632745409482267565260819", 10)
	//y, _ := new(big.Int).SetString("147946756881789318990833708069417712964", 10)
	//log.Println(y.Add(y, MODULUS))

	log.Println(x.Mod(x, MODULUS))
}
