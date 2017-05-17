package cryptolabs

import (
	"bytes"
	"crypto/sha1"
)

func HmacSHA1(key, message []byte) [20]byte {
	if len(key) > sha1.BlockSize {
		sum := sha1.Sum(key)
		key = sum[:]
	}
	if len(key) < sha1.BlockSize {
		key = append(key, bytes.Repeat([]byte{0}, sha1.BlockSize-len(key))...)
	}
	outerKeyPad := make([]byte, sha1.BlockSize)
	innerKeyPad := make([]byte, sha1.BlockSize)
	for i := 0; i < sha1.BlockSize; i++ {
		outerKeyPad[i] = 0x5c ^ key[i]
		innerKeyPad[i] = 0x36 ^ key[i]
	}
	innerHash := sha1.Sum(append(innerKeyPad, message...))
	outerHash := sha1.Sum(append(outerKeyPad, innerHash[:]...))
	return outerHash
}
