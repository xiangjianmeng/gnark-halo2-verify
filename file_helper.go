package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"os"
)

func storePkVk(pk groth16.ProvingKey, vk groth16.VerifyingKey) {
	var buf bytes.Buffer
	_, err := pk.WriteRawTo(&buf)
	if err != nil {
		panic(err)
	}
	err = storeBufferToFile("./pk.txt", &buf)
	if err != nil {
		panic(err)
	}

	var bufVkey bytes.Buffer
	_, err = vk.WriteRawTo(&bufVkey)
	if err != nil {
		panic(err)
	}
	err = storeBufferToFile("./vk.txt", &bufVkey)
	if err != nil {
		panic(err)
	}
}

func readPkVk() (groth16.ProvingKey, groth16.VerifyingKey) {
	pkBuf, err := readBufferFromFile("./pk.txt")
	if err != nil {
		panic(err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(pkBuf)
	if err != nil {
		panic(err)
	}

	vkeyBuf, err := readBufferFromFile("./vk.txt")
	if err != nil {
		panic(err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkeyBuf)
	if err != nil {
		panic(err)
	}
	return pk, vk
}

func storeBufferToFile(fileName string, buf *bytes.Buffer) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()

	_, err = buf.WriteTo(gzWriter)
	if err != nil {
		return err
	}

	fmt.Println("Data successfully compressed and written to file:", fileName)
	return nil
}

func readBufferFromFile(fileName string) (*bytes.Buffer, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(gzReader)
	if err != nil {
		return nil, err
	}

	return &buf, nil
}
