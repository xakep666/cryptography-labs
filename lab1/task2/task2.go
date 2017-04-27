package task2

import "errors"

func TrimPkcs7Pad(padded []byte) ([]byte, error) {
	padLength := padded[len(padded)-1]
	padding := padded[byte(len(padded))-padLength : len(padded)-1]
	//check padding
	for _, v := range padding {
		if v != padLength {
			return nil, errors.New("invalid padding")
		}
	}
	return padded[0 : len(padded)-len(padding)-1], nil
}
