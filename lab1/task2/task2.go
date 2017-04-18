package task2

import (
	"cryptolabs/lab1/task1"
	"errors"
	"strings"
	"unicode"
)

func TrimPkcs7Pad(padded string) (ret string, err error) {
	ret = strings.TrimRightFunc(padded, func(chr rune) bool {
		if !unicode.IsPrint(chr) {
			if chr != rune(task1.PadByte) {
				err = errors.New("invalid padding character found")
				return false
			}
			return true
		}
		return false
	})
	return
}
