package task4

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"cryptolabs"
	"cryptolabs/lab1/task1"
	"cryptolabs/lab1/task3"
	"math/rand"
	"time"
)

// true for ECB, false for CBC
func encryptEcbCbcRand(data []byte, blk cipher.Block) ([]byte, bool) {
	rand.Seed(time.Now().Unix())
	preffix := task3.RandByteArray(rand.Intn(5) + 5)
	suffix := task3.RandByteArray(rand.Intn(5) + 5)
	var mode cipher.BlockMode
	var isEcb bool
	if rand.Float32() < 0.5 {
		// CBC
		iv := make([]byte, blk.BlockSize())
		mode = cipher.NewCBCEncrypter(blk, iv)
		isEcb = false
	} else {
		// ECB
		mode = cryptolabs.NewECBEncrypter(blk)
		isEcb = true
	}
	if len(data)%mode.BlockSize() != 0 {
		data = task1.Pkcs7Pad(data, blk.BlockSize())
	}
	ret := make([]byte, len(data))
	mode.CryptBlocks(ret, data)
	ret = append(preffix, ret...)
	ret = append(ret, suffix...)
	return ret, isEcb
}

func guessIsEcb(cipherText []byte, blk cipher.Block) bool {
	maxMatches := 0
	for len(cipherText) > blk.BlockSize() {
		matches := 0
		curBlock := cipherText[:blk.BlockSize()]
		for i := blk.BlockSize(); i < len(cipherText); i += blk.BlockSize() {
			blockToCompare := cipherText[i : i+blk.BlockSize()]
			if bytes.Compare(curBlock, blockToCompare) == 0 {
				matches++
			}
		}
		if matches > maxMatches {
			maxMatches = matches
		}
		cipherText = cipherText[blk.BlockSize():]
	}
	return maxMatches > 1
}

func createPlainText(blk cipher.Block) []byte {
	ret := make([]byte, 5*blk.BlockSize())
	for i := 0; i < len(ret); i++ {
		ret[i] = 0xAE
	}
	return ret
}

// true if guessed
func EncryptAndGuess() (bool, error) {
	key := task3.RandByteArray(16)
	aes, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	plainText := createPlainText(aes)
	cipherText, isEcbEncr := encryptEcbCbcRand(plainText, aes)
	isEcbGuess := guessIsEcb(cipherText, aes)
	return isEcbEncr == isEcbGuess, nil
}
