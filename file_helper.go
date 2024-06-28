package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
)

func store_r1cs_to_file(fileName string, buf *bytes.Buffer) error {
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

func read_r1cs_from_file(fileName string) (*bytes.Buffer, error) {
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
