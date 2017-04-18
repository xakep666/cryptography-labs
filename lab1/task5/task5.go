package task5

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"cryptolabs"
	task12 "cryptolabs/lab0/task1"
	"cryptolabs/lab1/task1"
	"cryptolabs/lab1/task3"
)

const unknownStrBase64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkga" +
	"GFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQp" +
	"EaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

var mode cipher.BlockMode
var decodedB64Str []byte

func init() {
	blk, err := aes.NewCipher(task3.RandByteArray(16))
	if err != nil {
		panic(err)
	}
	mode = cryptolabs.NewECBEncrypter(blk)
	decodedB64Str, err = task12.DecodeBase64(unknownStrBase64)
	if err != nil {
		panic(err)
	}
}

func ecbWithSuffix(data []byte) []byte {
	data = append(data, decodedB64Str...)
	data = task1.Pkcs7Pad(data, mode.BlockSize())
	ret := make([]byte, len(data))
	mode.CryptBlocks(ret, data)
	return ret
}

func detectBlockSize(blackBox func([]byte) []byte) int {
	plainText := []byte{}
	for {
		plainText = append(plainText, byte(0xAE))
		cipherText := blackBox(append(plainText, plainText...))
		pLen := len(plainText)
		if bytes.Compare(cipherText[0:pLen], cipherText[pLen:2*pLen]) == 0 {
			return pLen
		}
	}
}

func bruteNextByte(blackBox func([]byte) []byte, blkSize int, knownBytes []byte) (byte, bool) {
	myStr := bytes.Repeat([]byte{0xAE}, blkSize-(len(knownBytes)%blkSize)-1)
	dict := map[string]byte{} // map[[]byte]byte
	for i := 0; i <= 0xFF; i++ {
		bfInput := append(myStr, knownBytes...)
		bfInput = append(bfInput, byte(i))
		cipherText := blackBox(bfInput)
		dict[string(cipherText[0:len(myStr)+len(knownBytes)+1])] = byte(i)
	}
	cipherText := blackBox(myStr)
	toExtractLength := len(myStr) + len(knownBytes) + 1
	if toExtractLength >= len(cipherText) {
		return 0, false
	}
	blk := string(cipherText[0:toExtractLength])
	for k, v := range dict {
		if k == blk {
			return v, true
		}
	}
	return 0, false
}

func ECBKeyLessRead() []byte {
	blkSize := detectBlockSize(ecbWithSuffix)
	decrypted := []byte{}
	for {
		b, ok := bruteNextByte(ecbWithSuffix, blkSize, decrypted)
		if !ok {
			break
		}
		decrypted = append(decrypted, b)
	}
	return decrypted
}
