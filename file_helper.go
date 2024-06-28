package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
)

func store_r1cs_to_file(fileName string, buf *bytes.Buffer) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, buf)
	if err != nil {
		return err
	}
	return nil
}

func read_r1cs_from_file(fileName string) (*bytes.Buffer, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	// 将读取的内容写入到 bytes.Buffer 中
	var buf bytes.Buffer
	buf.Write(data)

	return &buf, nil
}
