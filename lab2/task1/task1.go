package task1

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	task12 "cryptolabs/lab0/task1"
	"cryptolabs/lab1/task1"
	"cryptolabs/lab1/task2"
	"cryptolabs/lab1/task3"
	"math/rand"
)

var b64lines = []string{
	"V2l0aCB5b3VyIGZlZXQgaW4gdGhlIGFpciBhbmQgeW91ciBoZWFkIG9uIHRoZSBncm91bmQK",
	"VHJ5IHRoaXMgdHJpY2sgYW5kIHNwaW4gaXQhIFllYWhoIQo=",
	"WW91ciBoZWFkIHdpbGwgY29sbGFwc2UsIGJ1dCB0aGVyZSdzIG5vdGhpbmcgaW4gaXQK",
	"QW5kIHlvdSdsbCBhc2sgeW91cnNlbGY/Cg==",
	"V2hlcmUgaXMgbXkgbWluZD8K",
	"V2F5IG91dCwgaW4gdGhlIHdhdGVyIHNlZSBpdCBzd2ltbWluJyAK",
	"SSB3YXMgc3dpbW1pbicgaW4gdGhlIENhcnJpYmVhbgo=",
	"QW5pbWFscyB3b3VsZCBoaWRlIGJlaGluZCB0aGUgcm9ja3MuIFllYWhoIQo=",
	"RXhjZXB0IHRoZSBsaXR0bGUgZmlzaAo=",
	"QnV0IGhlIHRvbGQgbWUgZWFzdCB3YXMgd2VzdAo=",
	"VHJ5aW4nIHRvIHRhbGsgCg==",
}

var cph cipher.Block

func init() {
	c, err := aes.NewCipher(task3.RandByteArray(16))
	if err != nil {
		panic(err)
	}
	cph = c
}

func EncryptRandLineCBC() (cipherText, iv []byte) {
	line, err := task12.DecodeBase64(b64lines[rand.Intn(len(b64lines))])
	if err != nil {
		panic(err)
	}
	iv = task3.RandByteArray(cph.BlockSize())
	enc := cipher.NewCBCEncrypter(cph, iv)
	padded := task1.Pkcs7Pad(line, cph.BlockSize())
	cipherText = make([]byte, len(padded))
	enc.CryptBlocks(cipherText, padded)
	return
}

func DecryptCBC(cipherText, iv []byte) (validPadding bool) {
	dec := cipher.NewCBCDecrypter(cph, iv)
	paddedPlainText := make([]byte, len(cipherText))
	dec.CryptBlocks(paddedPlainText, cipherText)
	_, err := task2.TrimPkcs7Pad(paddedPlainText)
	validPadding = true
	if err != nil {
		validPadding = false
	}
	return
}

type paddingCheckFn func(ct, iv []byte) bool

func decPrevByteOfLastBlock(iv, cipherText []byte, paddingCheck paddingCheckFn, knownPlain []byte) (retKnownPlain byte) {
	ctLen := len(cipherText)
	blkLen := len(iv) // assume iv length is block length
	knownBytes := len(knownPlain)
	prefix := bytes.Repeat([]byte{0}, blkLen-knownBytes-1)
	prevBlockStart := ctLen - 2*blkLen
	prevBlockEnd := ctLen - blkLen
	for i := 0; i <= 0xFF; i++ {
		var ctPref []byte
		prevBlock := make([]byte, blkLen)
		if ctLen > blkLen {
			copy(prevBlock, cipherText[prevBlockStart:prevBlockEnd])
			ctPref = make([]byte, prevBlockStart)
			copy(ctPref, cipherText[:prevBlockStart])
		} else {
			copy(prevBlock, iv)
		}
		suffix := make([]byte, knownBytes)
		for j, v := range knownPlain {
			suffix[j] = v ^ byte(knownBytes+1) ^ prevBlock[blkLen-knownBytes+j]
		}
		myPrevBlock := append(prefix, prevBlock[blkLen-knownBytes-1]^byte(knownBytes+1)^byte(i))
		myPrevBlock = append(myPrevBlock, suffix...)
		myCipherText := append(ctPref, myPrevBlock...)
		myCipherText = append(myCipherText, cipherText[prevBlockEnd:]...)
		if paddingCheck(myCipherText, iv) {
			return byte(i)
		}
	}
	panic("we must not be here, is CBC used?")
	return 0
}

func decLastBlock(iv, cipherText []byte, paddingCheck paddingCheckFn) (knownPlain []byte) {
	for i := 0; i < len(iv); i++ {
		foundPlain := decPrevByteOfLastBlock(iv, cipherText, paddingCheck, knownPlain)
		knownPlain = append([]byte{foundPlain}, knownPlain...)

	}
	return
}

func DecLine(iv, cipherText []byte, paddingCheck paddingCheckFn) (knownPlain []byte) {
	ctLen := len(cipherText)
	blkLen := len(iv)
	// exploiting: brute-force plaintext byte to perform bit-flipping attack to get valid padding
	for i := 0; i < ctLen/blkLen; i++ {
		knownPlain = append(decLastBlock(iv, cipherText[:ctLen-i*blkLen], paddingCheck), knownPlain...)
	}
	knownPlain, err := task2.TrimPkcs7Pad(knownPlain)
	if err != nil {
		panic(err)
	}
	return
}
