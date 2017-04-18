package task1

import (
	"bytes"
)

const PadByte = byte(0x04)

func Pkcs7Pad(data []byte, blockSize int) []byte {
	padLength := (len(data)/blockSize+1)*blockSize - len(data)
	padBArr := []byte{PadByte}
	padding := bytes.Repeat(padBArr, padLength)
	return append(data, padding...)
}
