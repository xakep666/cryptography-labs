package task1

import (
	"crypto/aes"
	"crypto/cipher"
	"cryptolabs"
	"cryptolabs/lab0/task1"
	"cryptolabs/lab1/task3"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"
)

var ctr cipher.Stream
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
	ctr = cryptolabs.NewCTR(cph, nonce)
}

func loadFromFileAndDecode(path string) (data []byte, err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	var line string
	_, err = fmt.Fscanln(file, &line)
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		return
	}
	data, err = task1.DecodeBase64(line)
	return
}

func ReadAndEncryptText(path string) (cipherText []byte, err error) {
	plainText, err := loadFromFileAndDecode(path)
	if err != nil {
		return
	}
	cipherText = make([]byte, len(plainText))
	ctr.XORKeyStream(cipherText, plainText)
	return
}

func Edit(cipherText []byte, offset int, newText []byte) []byte {
	prefix := make([]byte, offset)
	newCipherText := make([]byte, len(prefix)+len(newText))
	cryptolabs.NewCTR(cph, nonce).XORKeyStream(newCipherText, append(prefix, newText...))
	ctPart := newCipherText[offset:]
	return append(append(cipherText[:offset], ctPart...), cipherText[offset+len(ctPart):]...)
}
