package task1

import (
	"strings"
)

const PadStr = "\x04"

func Pkcs7Pad(str string, blockSize int) (string) {
	padLength:= (len(str) / blockSize + 1) * blockSize - len(str)
	padding:=strings.Repeat(PadStr, padLength)
	return str+padding
}
