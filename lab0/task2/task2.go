package task2

import (
	"cryptolabs/lab0/task1"
	"encoding/hex"
	"errors"
)

func XorTwoArrays(buf1, buf2 []byte) ([]byte, error) {
	if len(buf1) != len(buf2) {
		return nil, errors.New("Arrays must have same length")
	}
	ret := make([]byte, len(buf1))
	for i := 0; i < len(ret); i++ {
		ret[i] = buf1[i] ^ buf2[i]
	}
	return ret, nil
}

func XorTwoHexStrings(str1, str2 string) (string, error) {
	buf1, err := task1.DecodeHexStr(str1)
	if err != nil {
		return "", err
	}
	buf2, err := task1.DecodeHexStr(str2)
	if err != nil {
		return "", err
	}
	ret, err := XorTwoArrays(buf1, buf2)
	return hex.EncodeToString(ret), err
}
