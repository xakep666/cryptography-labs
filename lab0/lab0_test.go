package main

import (
	"crypto/lab0/task1"
	"crypto/lab0/task2"
	"crypto/lab0/task3"
	"crypto/lab0/task4"
	"crypto/lab0/task5"
	"crypto/lab0/task6"
	"crypto/lab0/task7"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
	"crypto/lab0/task8"
)

func TestTask1(t *testing.T) {
	bytes, err := task1.DecodeHexStr("0000")
	assert.NoError(t, err)
	fmt.Println(hex.EncodeToString(bytes))
	b64string := task1.EncodeBase64(bytes)
	fmt.Println(b64string)
	bytes, err = task1.DecodeBase64(b64string)
	assert.NoError(t, err)
	fmt.Println(hex.EncodeToString(bytes))
}

func TestTask2(t *testing.T) {
	str1 := "8f29336f5e9af0919634f474d248addaf89f6e1f533752f52de2dae0ec3185f818c0892fdc873a69"
	str2 := "bf7962a3c4e6313b134229e31c0219767ff59b88584a303010ab83650a3b1763e5b314c2f1e2f166"
	hexString, err := task2.XorTwoHexStrings(str1, str2)
	assert.NoError(t, err)
	fmt.Println(hexString)
}

func TestTask3(t *testing.T) {
	str := "2b4a0605040d4a1e03070f4a0b0d05464a03044a0b4a0d0b060b12134a0c0b18464a0c0b184a0b1d0b1344444444"
	bfKeys := "abcdefghijklmnopqrstuvwxyz"
	bytes, err := hex.DecodeString(str)
	assert.NoError(t, err)
	decodedStr, key, err := task3.BruteForceOneByteXor(bytes, bfKeys)
	assert.NoError(t, err)
	fmt.Printf("%s;key %c\n", decodedStr, key)
}

func TestTask4(t *testing.T) {
	bfKeys:="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz !@#$%^&*(){}[]:;',./<>?=+`~\"\\|"
	decodedStr, key, line, err := task4.FindSingleXorStr("detectSingleXor16",bfKeys)
	assert.NoError(t, err)
	fmt.Printf("%s; key %c; line %d\n", decodedStr, key, line)
}

func TestTask5(t *testing.T) {
	str:="Never trouble about trouble until trouble troubles you!"
	key:="ICE"
	bytes := task5.XorRepitiveKey([]byte(str), []byte(key))
	fmt.Println(hex.EncodeToString(bytes))
}

func TestTask6(t *testing.T) {
	bfKeys:="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ,.:"
	err := task6.BruteForceBase64Encoded("breakRepeatedKeyXor.txt", bfKeys)
	assert.NoError(t, err)
}

func TestTask7(t *testing.T) {
	bytes, err := task7.DecryptBase64File("decryptAesEcb.txt", "YELLOW SUBMARINE")
	fmt.Println(string(bytes))
	assert.NoError(t, err)
}

func TestTask8(t *testing.T) {
	fmt.Println("Possible AES-128-ECB lines")
	err := task8.FindPossibleEcb("detectEcb.txt")
	assert.NoError(t, err)
}