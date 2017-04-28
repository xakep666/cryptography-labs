package task2

import "errors"

func TrimPkcs7Pad(padded []byte) ([]byte, error) {
	padLength := padded[len(padded)-1]
	if int(padLength) >= len(padded) || padLength == 0 {
		return nil, errors.New("invalid padding")
	}
	padding := padded[len(padded)-int(padLength):]
	//check padding
	for _, v := range padding {
		if v != padLength {
			return nil, errors.New("invalid padding")
		}
	}
	return padded[:len(padded)-int(padLength)], nil
}
