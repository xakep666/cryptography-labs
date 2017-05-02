package main

import (
	"cryptolabs/lab3/task1"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTask1(t *testing.T) {
	cipherText, err := task1.ReadAndEncryptText("Lab3_breakCtr4-b64.txt")
	if assert.NoError(t, err) {
		plainText := task1.Edit(cipherText, 0, cipherText)
		fmt.Println(string(plainText))
	}
}
