package main

import (
	"cryptolabs/lab1/task1"
	"cryptolabs/lab1/task2"
	"cryptolabs/lab1/task3"
	"cryptolabs/lab1/task4"
	"cryptolabs/lab1/task5"
	"cryptolabs/lab1/task6"
	"cryptolabs/lab1/task7"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestTask1(t *testing.T) {
	source := "YELLOW SUBMARINE"
	blockSize := 20
	target := "YELLOW SUBMARINE\x04\x04\x04\x04"
	padded := string(task1.Pkcs7Pad([]byte(source), blockSize))
	fmt.Println(padded)
	assert.Equal(t, target, padded)
}

func TestTask2(t *testing.T) {
	nonPadded, err := task2.TrimPkcs7Pad([]byte("ICE ICE BABY\x04\x04\x04\x04"))
	if assert.NoError(t, err) {
		assert.Equal(t, "ICE ICE BABY", string(nonPadded))
	}
	_, err = task2.TrimPkcs7Pad([]byte("ICE ICE BABY\x05\x05\x05\x05"))
	assert.Error(t, err)
	_, err = task2.TrimPkcs7Pad([]byte("ICE ICE BABY\x01\x02\x03\x04"))
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
	blkSize := task5.DetectBlockSize(task5.EcbWithSuffix)
	fmt.Println("Got block size", blkSize)
	fmt.Println("Decrypting...")
	decrypted := task5.ECBKeyLessRead(task5.EcbWithSuffix, blkSize)
	fmt.Println(string(decrypted))
}

func TestTask6(t *testing.T) {
	profile := task6.ProfileFor("mymail@gmail.com")
	fmt.Println("Generated Profile:", profile)
	patchedProfile := task6.SpecialPadEmail(profile)
	fmt.Println("Preared profile:", patchedProfile)
	encryptedProfile := task6.EncryptProfile(patchedProfile)
	patchedEncryptedProfile := task6.ReplaceRoleInCipherText(encryptedProfile, "admin")
	fmt.Println("Decrypted patched profile")
	task6.DecryptAndPrintProfile(patchedEncryptedProfile)
}

func TestTask7(t *testing.T) {
	blkSize := task5.DetectBlockSize(task7.EncryptWithRandPrefix)
	fmt.Println("Got block size", blkSize)
	prefixSize := task7.FindPrefixSize(task7.EncryptWithRandPrefix, blkSize)
	fmt.Println("Got prefix size", prefixSize)
	fmt.Println("Decrypting...")
	decrypted := task7.ECBKeyLessReadWithPrefix(task7.EncryptWithRandPrefix, blkSize, prefixSize)
	fmt.Println(string(decrypted))
}
