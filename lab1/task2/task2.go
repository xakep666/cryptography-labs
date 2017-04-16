package task2

import (
	"strings"
	"unicode"
	"crypto/lab1/task1"
	"errors"
)

func TrimPkcs7Pad(padded string) (ret string, err error) {
	ret=strings.TrimRightFunc(padded, func (chr rune) bool{
		if !unicode.IsPrint(chr) {
			if chr!=rune(task1.PadStr[0]) {
				err=errors.New("invalid padding character found")
				return false
			}
			return true
		}
		return false
	})
	return
}
