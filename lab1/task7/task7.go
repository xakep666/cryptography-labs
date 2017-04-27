package task7

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"cryptolabs"
	"cryptolabs/lab0/task1"
	task12 "cryptolabs/lab1/task1"
	"cryptolabs/lab1/task2"
	"cryptolabs/lab1/task3"
	"cryptolabs/lab1/task5"
	"math/rand"
	"time"
)

const (
	blkSize   = 16
	minPrefix = 16
	maxPrefix = 32
)

var (
	ecbEnc cipher.BlockMode
	prefix []byte
)

func init() {
	cph, err := aes.NewCipher(task3.RandByteArray(blkSize))
	if err != nil {
		panic(err)
	}
	ecbEnc = cryptolabs.NewECBEncrypter(cph)
	rand.Seed(time.Now().Unix())
	prefixLen := rand.Intn(maxPrefix-minPrefix) + minPrefix
	prefix = task3.RandByteArray(prefixLen)
}

func EncryptWithRandPrefix(myData []byte) []byte {
	plainText := append(prefix, myData...)
	unknownSuffix, err := task1.DecodeBase64(task5.UnknownStrBase64)
	if err != nil {
		panic(err)
	}
	plainText = append(plainText, unknownSuffix...)
	plainText = task12.Pkcs7Pad(plainText, ecbEnc.BlockSize())
	ret := make([]byte, len(plainText))
	ecbEnc.CryptBlocks(ret, plainText)
	return ret
}

func findPrefixBlocksSize(blackBox func([]byte) []byte, blkSize int) int {
	cipherText1 := blackBox([]byte{})
	cipherText2 := blackBox([]byte{0xAD})
	for i := 0; i < len(cipherText1); i += blkSize {
		if !bytes.Equal(cipherText1[i:i+blkSize], cipherText2[i:i+blkSize]) {
			return i
		}
	}
	return -1
}

func FindPrefixSize(blackBox func([]byte) []byte, blkSize int) int {
	hasEqualNeighbourBlock := func(data []byte) bool {
		for i := 0; i < len(data)-blkSize; i += blkSize {
			if bytes.Equal(data[i:i+blkSize], data[i+blkSize:i+2*blkSize]) {
				return true
			}
		}
		return false
	}

	plainText := bytes.Repeat([]byte{0xAE}, 2*blkSize)
	ret := findPrefixBlocksSize(blackBox, blkSize)
	for i := 0; i < blkSize; i++ {
		cipherText := blackBox(plainText)
		if hasEqualNeighbourBlock(cipherText) {
			if i == 0 {
				return ret
			} else {
				return ret + blkSize - i
			}
		}
		plainText = append(plainText, 0xAE)
	}
	panic("Not using ECB")
	return -1
}

func bruteNextByte(blackBox func([]byte) []byte, blkSize, prefixSize int, knownBytes []byte) (byte, bool) {
	v1 := blkSize - (prefixSize % blkSize)
	v2 := blkSize - (len(knownBytes) % blkSize) - 1
	v3 := prefixSize - (prefixSize % blkSize)
	plainText := bytes.Repeat([]byte{0xAE}, v1+v2)
	extractStart := v3 + v1
	extractEnd := v3 + v1 + v2 + len(knownBytes) - 1
	cipherText := blackBox(plainText)
	if extractEnd >= len(cipherText) {
		return 0, false
	}
	blockToExtract := cipherText[extractStart:extractEnd]
	for i := 0; i <= 0xFF; i++ {
		bfInput := append(plainText, knownBytes...)
		bfInput = append(bfInput, byte(i))
		if bytes.Equal(blockToExtract, blackBox(bfInput)[extractStart:extractEnd]) {
			return byte(i), true
		}
	}
	return 0, false
}

func ECBKeyLessReadWithPrefix(blackBox func([]byte) []byte, blkSize, prefixSize int) []byte {
	decrypted := []byte{}
	for {
		b, ok := bruteNextByte(blackBox, blkSize, prefixSize, decrypted)
		if !ok {
			break
		}
		decrypted = append(decrypted, b)
	}
	ret, _ := task2.TrimPkcs7Pad(decrypted)
	return ret
}
