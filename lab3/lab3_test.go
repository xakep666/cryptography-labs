package main

import (
	"cryptolabs"
	"cryptolabs/lab3/task1"
	"cryptolabs/lab3/task2"
	"cryptolabs/lab3/task3"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestTask1(t *testing.T) {
	cipherText, err := task1.ReadAndEncryptText("Lab3_breakCtr4-b64.txt")
	if assert.NoError(t, err) {
		plainText := task1.Edit(cipherText, 0, cipherText)
		fmt.Println(string(plainText))
	}
}

func TestTask2(t *testing.T) {
	exploit := "aa;admin=true;"
	badCharPositions, userInput := task2.GenerateUserData(exploit)
	cipherText := task2.EncryptParams(userInput)
	newCipherText := task2.ReplaceInCipherText(cipherText, badCharPositions)
	newUrl := task2.DecryptParams(newCipherText)
	fmt.Println(newUrl)
	assert.True(t, strings.Contains(newUrl, exploit))
}

func TestTask3(t *testing.T) {
	myInput := strings.Repeat("a", len(task3.GeneratedKey))
	cipherText := task3.GenerateAndEncryptUrl(myInput)
	patched := task3.PatchCipherText(cipherText)
	decryptedUrl, err := task3.DecryptUrl(patched)
	assert.Error(t, err)
	extractedKey := task3.ExtractKey(decryptedUrl)
	assert.Equal(t, task3.GeneratedKey, extractedKey)
}

func TestMySHA1(t *testing.T) {
	testSet := []struct {
		msg  []byte
		hash [20]byte
	}{
		{[]byte("The quick brown fox jumps over the lazy dog"),
			[20]byte{0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12}},
	}
	for _, v := range testSet {
		assert.Equal(t, v.hash, cryptolabs.NewSHA1(v.msg).Digest())
	}
}
