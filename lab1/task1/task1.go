package task1

import (
	"bytes"
)

func Pkcs7Pad(data []byte, blockSize int) []byte {
	padLength := (len(data)/blockSize+1)*blockSize - len(data)
	padBArr := []byte{byte(padLength)}
	padding := bytes.Repeat(padBArr, padLength)
	return append(data, padding...)
}
