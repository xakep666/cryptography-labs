package task1

import (
	"errors"
	"regexp"
	"strings"
)

var hexRegex = regexp.MustCompile("^[0-9a-z]*$")
var base64Regex = regexp.MustCompile("^[A-Za-z0-9+/]*={0,3}$")
const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
var base64Map = map[rune]byte{}

func init() {
	// generate base64 map
	for idx, char := range base64Alphabet {
		base64Map[char]=byte(idx)
	}
}


func DecodeHexStr(str string) ([]byte, error) {
	str = strings.ToLower(str)
	if !hexRegex.MatchString(str) {
		return nil, errors.New("String contains invalid characters")
	}
	if len(str)%2 != 0 {
		return nil, errors.New("String must contain odd number of chars")
	}
	ret := make([]byte, len(str)/2)
	for i := 0; i < len(str)/2; i++ {
		if (str[2*i] <= 'f') && (str[2*i] >= 'a') {
			ret[i] |= (str[2*i] - 'a' + 0xA) << 4
		} else {
			ret[i] |= (str[2*i] - '0') << 4
		}
		if (str[2*i+1] <= 'f') && (str[2*i+1] >= 'a') {
			ret[i] |= str[2*i+1] - 'a' + 0xA
		} else {
			ret[i] |= str[2*i+1] - '0'
		}
	}
	return ret, nil
}

func EncodeBase64(buf []byte) string {
	sidx := 0
	n := (len(buf) / 3) * 3
	ret := []byte{}
	for sidx < n {
		// 3x8 source bits to 4 bytes
		val := uint(buf[sidx+0])<<16 | uint(buf[sidx+1])<<8 | uint(buf[sidx+2])
		ret = append(ret, base64Alphabet[val>>18&0x3F], base64Alphabet[val>>12&0x3f], base64Alphabet[val>>6&0x3f], base64Alphabet[val&0x3F])
		sidx += 3
	}
	remain := len(buf) - sidx
	if remain == 0 {
		return string(ret)
	}
	// add remaining bits
	val := uint(buf[sidx+0]) << 16
	if remain == 2 {
		val |= uint(buf[sidx+1]) << 8
	}
	ret = append(ret, base64Alphabet[val>>18&0x3F], base64Alphabet[val>>12&0x3F])
	switch remain {
	case 2:
		ret = append(ret, base64Alphabet[val>>6&0x3F])
		ret = append(ret, []byte("=")...)
	case 1:
		ret = append(ret, []byte("==")...)
	}
	return string(ret)
}

func DecodeBase64(str string) ([]byte, error) {
	if !base64Regex.MatchString(str) || len(str)%4 != 0{
		return nil, errors.New("Invalid base64-string")
	}

	ret:=make([]byte, len(str)*6/8)
	str = strings.Trim(str, "=") //trim padding
	sidx:=0
	didx:=0
	for ;sidx<(len(str) / 4) * 4;sidx+=4 {
		//convert 4 letters to 3 bytes
		ret[didx+0]|=base64Map[rune(str[sidx+0])]<<2
		ret[didx+0]|=(base64Map[rune(str[sidx+1])]&0x30)>>4
		ret[didx+1]|=(base64Map[rune(str[sidx+1])]&0xF)<<4
		ret[didx+1]|=(base64Map[rune(str[sidx+2])]&0x3C)>>2
		ret[didx+2]|=(base64Map[rune(str[sidx+2])]&0x3)<<6
		ret[didx+2]|=base64Map[rune(str[sidx+3])]
		didx+=3
	}

	// add remaining
	switch len(str)%4 {
	case 3:
		ret[didx+1]|=(base64Map[rune(str[sidx+2])]&0x3C)>>2
		ret[didx+2]|=(base64Map[rune(str[sidx+2])]&0x3)<<6
		fallthrough
	case 2:
		ret[didx+0]|=(base64Map[rune(str[sidx+1])]&0x30)>>4
		ret[didx+1]|=(base64Map[rune(str[sidx+1])]&0xF)<<4
		fallthrough
	case 1:
		ret[didx+0]|=base64Map[rune(str[sidx+0])]<<2
	}
	return ret[:len(ret)-len(str)%4], nil
}
