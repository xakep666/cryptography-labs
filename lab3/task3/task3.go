package task3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"cryptolabs/lab1/task1"
	"cryptolabs/lab1/task2"
	"cryptolabs/lab1/task3"
	"errors"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

const (
	leftPart  = "comment1=cooking%20MCs;userdata="
	rightPart = ";comment2=%20like%20a%20pound%20of%20bacon"
)

var cbcEnc, cbcDec cipher.BlockMode
var GeneratedKey []byte

func init() {
	rand.Seed(time.Now().Unix())
	GeneratedKey = task3.RandByteArray(16)
	cph, err := aes.NewCipher(GeneratedKey)
	if err != nil {
		panic(err)
	}
	cbcEnc, cbcDec = cipher.NewCBCEncrypter(cph, GeneratedKey), cipher.NewCBCDecrypter(cph, GeneratedKey)
}

func GenerateAndEncryptUrl(userData string) []byte {
	userData = strings.Replace(userData, ";", "%3B", -1)
	userData = strings.Replace(userData, "=", "%3D", -1)
	padded := task1.Pkcs7Pad([]byte(leftPart+userData+rightPart), cbcEnc.BlockSize())
	ret := make([]byte, len(padded))
	cbcEnc.CryptBlocks(ret, padded)
	return ret
}

func DecryptUrl(cipherText []byte) (url string, err error) {
	plain := make([]byte, len(cipherText))
	cbcDec.CryptBlocks(plain, cipherText)
	url = string(plain)
	if err != nil {
		return
	}
	// check for bad chars
	for _, v := range plain {
		if !strconv.IsPrint(rune(v)) {
			err = errors.New("unexpected chars in url")
			return
		}
	}
	unpadded, err := task2.TrimPkcs7Pad(plain)
	url = string(unpadded)
	return
}

func PatchCipherText(cipherText []byte) (ret []byte) {
	a := append(cipherText[:cbcDec.BlockSize()], bytes.Repeat([]byte{0}, cbcDec.BlockSize())...)
	b := append(a, cipherText[:cbcDec.BlockSize()]...)
	return append(b, cipherText[:3*cbcDec.BlockSize()]...)
}

func ExtractKey(url string) (key []byte) {
	key = make([]byte, cbcDec.BlockSize())
	byteUrl := []byte(url)
	for i := 0; i < len(key); i++ {
		key[i] = byteUrl[i] ^ byteUrl[2*len(key)+i]
	}
	return
}
