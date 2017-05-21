package main

import (
	"bytes"
	"cryptolabs"
	task32 "cryptolabs/lab1/task3"
	"cryptolabs/lab3/task1"
	"cryptolabs/lab3/task2"
	"cryptolabs/lab3/task3"
	"cryptolabs/lab3/task4"
	"cryptolabs/lab3/task5"
	"cryptolabs/lab3/task7"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
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
		{[]byte("sha"),
			[20]byte{0xd8, 0xf4, 0x59, 0x03, 0x20, 0xe1, 0x34, 0x3a, 0x91, 0x5b, 0x63, 0x94, 0x17, 0x06, 0x50, 0xa8, 0xf3, 0x5d, 0x69, 0x26}},
	}
	for _, v := range testSet {
		assert.Equal(t, v.hash, cryptolabs.NewSHA1(v.msg).Digest())
	}
}

func TestTask4(t *testing.T) {
	key := task32.RandByteArray(16)
	msg := []byte("some message")
	digest := task4.Sha1Mac(key, msg)
	assert.True(t, task4.CheckSha1Mac(key, msg, digest))
	msg[2] = 0xFE
	msg[0] = 0x00
	assert.False(t, task4.CheckSha1Mac(key, msg, digest))
}

func TestTask5(t *testing.T) {
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	suffix := []byte(";admin=true")
	digest := task5.SignMessage(msg)
	assert.True(t, task5.CheckSignature(msg, digest))
	forgedMessage, forgedDigest := task5.AddSuffixAndResign(msg, suffix, digest)
	fmt.Printf("%x\n%v\n%x\n", forgedDigest, len(append(cryptolabs.Sha1padding(append(task5.Key, msg...)), suffix...)), task5.SignMessage(forgedMessage))
	assert.NotNil(t, forgedMessage)
	assert.True(t, task5.CheckSignature(forgedMessage, forgedDigest))
	assert.True(t, bytes.Contains(forgedMessage, suffix))
}

func TestHmacSHA1(t *testing.T) {
	testSet := []struct {
		key, message string
		mac          [20]byte
	}{
		{"", "",
			[20]byte{0xfb, 0xdb, 0x1d, 0x1b, 0x18, 0xaa, 0x6c, 0x08, 0x32, 0x4b, 0x7d, 0x64, 0xb7, 0x1f, 0xb7, 0x63, 0x70, 0x69, 0x0e, 0x1d}},
		{"key", "The quick brown fox jumps over the lazy dog",
			[20]byte{0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a, 0x7a, 0x36, 0xf7, 0x0a, 0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9}},
	}
	for _, v := range testSet {
		assert.Equal(t, v.mac, cryptolabs.HmacSHA1([]byte(v.key), []byte(v.message)))
	}
}

func TestTask7(t *testing.T) {
	address := "127.0.0.1:8000"
	urlPattern := "http://" + address + "/test?file=%s&signature=%x"
	testMsg := []byte("message")
	validHmac := cryptolabs.HmacSHA1(task7.Key, testMsg)
	fmt.Printf("Valid hmac for message %s: % X\n", testMsg, validHmac)
	err := task7.StartServer(address)
	defer task7.StopServer()
	assert.NoError(t, err)
	resp, err := http.Get(fmt.Sprintf(urlPattern, testMsg, validHmac))
	if assert.NoError(t, err) {
		text, err := ioutil.ReadAll(resp.Body)
		fmt.Printf("%s %v\n", text, err)
		assert.Equal(t, 200, resp.StatusCode)
		resp.Body.Close()
	}
	resp, err = http.Get(fmt.Sprintf(urlPattern, testMsg, 0xDD))
	if assert.NoError(t, err) {
		text, err := ioutil.ReadAll(resp.Body)
		fmt.Printf("%s %v\n", text, err)
		assert.Equal(t, resp.StatusCode, 422)
		resp.Body.Close()
	}
	calculatedHmac := task7.CalculateHmac(testMsg, urlPattern)
	assert.Equal(t, validHmac, calculatedHmac)
}
