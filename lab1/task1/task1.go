package task1

import (
	"bytes"
)

func Pkcs7Pad(data []byte, blockSize int) []byte {
	padLength := blockSize - (len(data) % blockSize)
	padBArr := []byte{byte(padLength)}
	padding := bytes.Repeat(padBArr, padLength)
	return append(data, padding...)
}
