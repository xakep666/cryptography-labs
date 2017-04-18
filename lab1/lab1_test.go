package main

import (
	"cryptolabs/lab1/task1"
	"cryptolabs/lab1/task2"
	"cryptolabs/lab1/task3"
	"cryptolabs/lab1/task4"
	"cryptolabs/lab1/task5"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestTask1(t *testing.T) {
	source := "YELLOW SUBMARINE"
	blockSize := 20
	target := "YELLOW SUBMARINE\x04\x04\x04\x04"
	padded := task1.Pkcs7Pad([]byte(source), blockSize)
	assert.Equal(t, target, padded)
}

func TestTask2(t *testing.T) {
	nonPadded, err := task2.TrimPkcs7Pad("ICE ICE BABY\x04\x04\x04\x04")
	if assert.NoError(t, err) {
		assert.Equal(t, "ICE ICE BABY", nonPadded)
	}
	_, err = task2.TrimPkcs7Pad("ICE ICE BABY\x05\x05\x05\x05")
	assert.Error(t, err)
	_, err = task2.TrimPkcs7Pad("ICE ICE BABY\x01\x02\x03\x04")
	assert.Error(t, err)
}

func TestTask3(t *testing.T) {
	exploit := "&admin=true&"
	exploited, err := task3.ExploitCbc(exploit)
	assert.NoError(t, err)
	assert.True(t, strings.Contains(exploited, exploit))
	fmt.Println(exploited)
}

func TestTask4(t *testing.T) {
	guessed, err := task4.EncryptAndGuess()
	if assert.NoError(t, err) {
		assert.True(t, guessed)
	}
}

func TestTask5(t *testing.T) {
	decrypted := task5.ECBKeyLessRead()
	fmt.Println(string(decrypted))
}
