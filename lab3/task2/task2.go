package task2

import (
	"crypto/aes"
	"crypto/cipher"
	"cryptolabs"
	"cryptolabs/lab1/task3"
	"math/rand"
	"strings"
	"time"
)

const (
	leftPart  = "comment1=cooking%20MCs;userdata="
	rightPart = ";comment2=%20like%20a%20pound%20of%20bacon"
	badChars  = ";="
)

var cph cipher.Block
var nonce uint64

func init() {
	rand.Seed(time.Now().Unix())
	var err error
	cph, err = aes.NewCipher(task3.RandByteArray(16))
	if err != nil {
		panic(err)
	}
	nonce = uint64(rand.Int63())
}

func EncryptParams(userData string) (ret []byte) {
	userData = strings.Replace(userData, ";", "%3B", -1)
	userData = strings.Replace(userData, "=", "%3D", -1)
	params := []byte(leftPart + userData + rightPart)
	ret = make([]byte, len(params))
	cryptolabs.NewCTR(cph, nonce).XORKeyStream(ret, params)
	return
}

func DecryptParams(cipherText []byte) string {
	ret := make([]byte, len(cipherText))
	cryptolabs.NewCTR(cph, nonce).XORKeyStream(ret, cipherText)
	return string(ret)
}

func GenerateUserData(exploit string) (badCharPositions map[int]byte, userData string) {
	badCharPositions = make(map[int]byte)
	charToReplace := byte('X')
	userDataByte := []byte(exploit)
	for k, v := range exploit {
		if strings.ContainsRune(badChars, v) {
			badCharPositions[len(leftPart)+k] = charToReplace ^ byte(v)
			userDataByte[k] = charToReplace
		}
	}
	userData = string(userDataByte)
	return
}

func ReplaceInCipherText(cipherText []byte, badCharPositions map[int]byte) []byte {
	ret := make([]byte, len(cipherText))
	copy(ret, cipherText)
	for pos, replace := range badCharPositions {
		ret[pos] ^= replace
	}
	return ret
}
