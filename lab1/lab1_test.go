package main

import (
	"testing"
	"crypto/lab1/task1"
	"github.com/stretchr/testify/assert"
	"crypto/lab1/task2"
	"crypto/lab1/task3"
	"fmt"
	"strings"
)

func TestTask1(t *testing.T) {
	source:="YELLOW SUBMARINE"
	blockSize:=20
	target:="YELLOW SUBMARINE\x04\x04\x04\x04"
	padded:=task1.Pkcs7Pad(source, blockSize)
	assert.Equal(t, target, padded)
}

func TestTask2(t *testing.T) {
	nonPadded, err:=task2.TrimPkcs7Pad("ICE ICE BABY\x04\x04\x04\x04")
	if assert.NoError(t, err) {
		assert.Equal(t, "ICE ICE BABY", nonPadded)
	}
	_, err=task2.TrimPkcs7Pad("ICE ICE BABY\x05\x05\x05\x05")
	assert.Error(t, err)
	_, err=task2.TrimPkcs7Pad("ICE ICE BABY\x01\x02\x03\x04")
	assert.Error(t, err)
}

func TestTask3(t *testing.T) {
	exploit:=";admin=true;"
	exploited, err:=task3.ExploitCbc(exploit)
	exploited = strings.TrimRight(exploited, task1.PadStr)
	assert.NoError(t, err)
	assert.True(t, strings.Contains(exploited, exploit))
	fmt.Println(exploited)
}