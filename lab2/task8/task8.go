package task8

import (
	"bytes"
	"cryptolabs"
	"cryptolabs/lab1/task3"
	"encoding/binary"
	"math/rand"
	"time"
)

var Key uint16
var prefix []byte

func init() {
	rand.Seed(time.Now().Unix())
	Key = uint16(rand.Uint32())
	prefix = task3.RandByteArray(rand.Intn(20-4) + 4)
}

type MT19937Cipher struct {
	rng      cryptolabs.MT19937
	keyBytes []byte
}

func NewMT19937Cipher(key uint16) (ret MT19937Cipher) {
	ret.rng.Seed(uint32(key) & 0xFFFF)
	return
}

func (mc *MT19937Cipher) Crypt(input []byte) (output []byte) {
	keyStream := mc.keyBytes
	// extend Key stream to input length
	for len(keyStream) < len(input) {
		keyBlock := make([]byte, 4)
		binary.LittleEndian.PutUint32(keyBlock, mc.rng.Uint32())
		keyStream = append(keyStream, keyBlock...)
	}
	if len(keyStream) > len(input) {
		mc.keyBytes = keyStream[len(input):]
		keyStream = keyStream[:len(input)]
	}
	output = make([]byte, len(input))
	for k, v := range input {
		output[k] = v ^ keyStream[k]
	}
	return
}

func EncryptionBlackBox(plainText []byte) []byte {
	cph := NewMT19937Cipher(Key)
	return cph.Crypt(append(prefix, plainText...))
}

func RecoverKey(blackBox func([]byte) []byte) uint16 {
	ptByte := byte(0xE0)
	plainText := bytes.Repeat([]byte{ptByte}, 14)
	cipherText := blackBox(plainText)
	prefixLen := len(cipherText) - len(plainText)
	for i := 0; i <= 0xFFFF; i++ {
		cipher := NewMT19937Cipher(uint16(i))
		myPlainText := bytes.Repeat([]byte{ptByte}, len(cipherText))
		myCipherText := cipher.Crypt(myPlainText)
		if bytes.Equal(cipherText[prefixLen:], myCipherText[prefixLen:]) {
			return uint16(i)
		}
	}
	panic("We shuould not be here")
	return 0
}

func GenerateTimeBasedToken() []byte {
	seed := uint16(time.Now().UnixNano() / int64(time.Second))
	cph := NewMT19937Cipher(seed)
	plainText := make([]byte, rand.Intn(20-4)+4)
	return cph.Crypt(plainText)
}

func IsTokenForNow(token []byte) bool {
	seed := uint16(time.Now().UnixNano() / int64(time.Second))
	cph := NewMT19937Cipher(seed)
	return bytes.Equal(token, cph.Crypt(make([]byte, len(token))))
}
