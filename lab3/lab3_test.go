package main

import (
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
