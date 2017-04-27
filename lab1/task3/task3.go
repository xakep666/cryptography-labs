package task3

import (
	"crypto/aes"
	"crypto/cipher"
	"cryptolabs/lab1/task1"
	"cryptolabs/lab1/task2"
	"errors"
	"math/rand"
	"strings"
	"time"
)

const comment1 = "cooking%20MCs;userdata="
const comment2 = "%20like%20a%20pound%20of%20bacon"
const inputStr = "a"

func RandByteArray(keySize int) []byte {
	ret := make([]byte, keySize)
	rand.Seed(time.Now().Unix())
	for i := 0; i < len(ret); i++ {
		ret[i] = byte(rand.Int())
	}
	return ret
}

func encryptInput(input string, key []byte, block cipher.Block) ([]byte, error) {
	iv := make([]byte, block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, iv)
	paddedInput := task1.Pkcs7Pad([]byte(comment1+input+comment2), block.BlockSize())
	ret := make([]byte, len(paddedInput))
	if len(paddedInput)%block.BlockSize() != 0 {
		return nil, errors.New("input must be padded")
	}
	mode.CryptBlocks(ret, paddedInput)
	return ret, nil
}

func decryptData(data []byte, key []byte, block cipher.Block) string {
	iv := make([]byte, block.BlockSize())
	mode := cipher.NewCBCDecrypter(block, iv)
	ret := make([]byte, len(data))
	mode.CryptBlocks(ret, data)
	return string(ret)
}

func findBlockStartToCorrupt(block cipher.Block) int {
	clen := len(comment1)
	blk := block.BlockSize()
	return (clen/blk + 1) * blk
}

func findMinimalInput(block cipher.Block) int {
	return findBlockStartToCorrupt(block) - len(comment1)
}

func patch(exploit string, cipherText []byte) (patchedText []byte) {
	i := 0
	for ; i < len(exploit); i++ {
		patchedText = append(patchedText, cipherText[i]^inputStr[0]^exploit[i])
	}
	return append(patchedText, cipherText[i:]...)
}

func ExploitCbc(exploit string) (string, error) {
	key := RandByteArray(16)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(exploit) > block.BlockSize() {
		return "", errors.New("exploit length must be less or equal to block size")
	}
	cipherText, err := encryptInput(strings.Repeat(inputStr, 2*(len(exploit)+findMinimalInput(block))), key, block)
	if err != nil {
		return "", err
	}
	start := findBlockStartToCorrupt(block)
	cipherPatch := patch(exploit, cipherText[start:])
	cipherText = append(cipherText[:start], cipherPatch...)
	decrypted := decryptData(cipherText, key, block)
	ret, err := task2.TrimPkcs7Pad([]byte(decrypted))
	return string(ret), err
}
