package task3

import (
	"bytes"
	"crypto/aes"
	"cryptolabs"
	"cryptolabs/lab0/task1"
	"cryptolabs/lab1/task3"
	"strings"
)

var b64Strings = []string{
	"SXQgd2FzIG1hbnkgYW5kIG1hbnkgYSB5ZWFyIGFnbywK",
	"SW4gYSBraW5nZG9tIGJ5IHRoZSBzZWEsCg==",
	"VGhhdCBhIG1haWRlbiB0aGVyZSBsaXZlZCB3aG9tIHlvdSBtYXkga25vdwo=",
	"QnkgdGhlIG5hbWUgb2YgQW5uYWJlbCBMZWU7Cg==",
	"QW5kIHRoaXMgbWFpZGVuIHNoZSBsaXZlZCB3aXRoIG5vIG90aGVyIHRob3VnaHQK",
	"VGhhbiB0byBsb3ZlIGFuZCBiZSBsb3ZlZCBieSBtZS4K",
	"SSB3YXMgYSBjaGlsZCBhbmQgc2hlIHdhcyBhIGNoaWxkLAo=",
	"SW4gdGhpcyBraW5nZG9tIGJ5IHRoZSBzZWEsCg==",
	"QnV0IHdlIGxvdmVkIHdpdGggYSBsb3ZlIHRoYXQgd2FzIG1vcmUgdGhhbiBsb3Zl4oCUCg==",
	"SSBhbmQgbXkgQW5uYWJlbCBMZWXigJQK",
	"V2l0aCBhIGxvdmUgdGhhdCB0aGUgd2luZ8OoZCBzZXJhcGhzIG9mIEhlYXZlbgo=",
	"Q292ZXRlZCBoZXIgYW5kIG1lLgo=",
	"QW5kIHRoaXMgd2FzIHRoZSByZWFzb24gdGhhdCwgbG9uZyBhZ28sCg==",
	"SW4gdGhpcyBraW5nZG9tIGJ5IHRoZSBzZWEsCg==",
	"QSB3aW5kIGJsZXcgb3V0IG9mIGEgY2xvdWQsIGNoaWxsaW5nCg==",
	"TXkgYmVhdXRpZnVsIEFubmFiZWwgTGVlOwo=",
	"U28gdGhhdCBoZXIgaGlnaGJvcm4ga2luc21lbiBjYW1lCg==",
	"QW5kIGJvcmUgaGVyIGF3YXkgZnJvbSBtZSwK",
	"VG8gc2h1dCBoZXIgdXAgaW4gYSBzZXB1bGNocmUK",
	"SW4gdGhpcyBraW5nZG9tIGJ5IHRoZSBzZWEuCg==",
	"VGhlIGFuZ2Vscywgbm90IGhhbGYgc28gaGFwcHkgaW4gSGVhdmVuLAo=",
	"V2VudCBlbnZ5aW5nIGhlciBhbmQgbWXigJQK",
	"WWVzIeKAlHRoYXQgd2FzIHRoZSByZWFzb24gKGFzIGFsbCBtZW4ga25vdywK",
	"SW4gdGhpcyBraW5nZG9tIGJ5IHRoZSBzZWEpCg==",
	"VGhhdCB0aGUgd2luZCBjYW1lIG91dCBvZiB0aGUgY2xvdWQgYnkgbmlnaHQsCg==",
	"Q2hpbGxpbmcgYW5kIGtpbGxpbmcgbXkgQW5uYWJlbCBMZWUuCg==",
	"QnV0IG91ciBsb3ZlIGl0IHdhcyBzdHJvbmdlciBieSBmYXIgdGhhbiB0aGUgbG92ZQo=",
	"T2YgdGhvc2Ugd2hvIHdlcmUgb2xkZXIgdGhhbiB3ZeKAlAo=",
	"T2YgbWFueSBmYXIgd2lzZXIgdGhhbiB3ZeKAlAo=",
	"QW5kIG5laXRoZXIgdGhlIGFuZ2VscyBpbiBIZWF2ZW4gYWJvdmUK",
	"Tm9yIHRoZSBkZW1vbnMgZG93biB1bmRlciB0aGUgc2VhCg==",
	"Q2FuIGV2ZXIgZGlzc2V2ZXIgbXkgc291bCBmcm9tIHRoZSBzb3VsCg==",
	"T2YgdGhlIGJlYXV0aWZ1bCBBbm5hYmVsIExlZTsK",
	"Rm9yIHRoZSBtb29uIG5ldmVyIGJlYW1zLCB3aXRob3V0IGJyaW5naW5nIG1lIGRyZWFtcwo=",
	"T2YgdGhlIGJlYXV0aWZ1bCBBbm5hYmVsIExlZTsK",
	"QW5kIHRoZSBzdGFycyBuZXZlciByaXNlLCBidXQgSSBmZWVsIHRoZSBicmlnaHQgZXllcwo=",
	"T2YgdGhlIGJlYXV0aWZ1bCBBbm5hYmVsIExlZTsK",
	"QW5kIHNvLCBhbGwgdGhlIG5pZ2h0LXRpZGUsIEkgbGllIGRvd24gYnkgdGhlIHNpZGUK",
	"T2YgbXkgZGFybGluZ+KAlG15IGRhcmxpbmfigJRteSBsaWZlIGFuZCBteSBicmlkZSwK",
	"SW4gaGVyIHNlcHVsY2hyZSB0aGVyZSBieSB0aGUgc2Vh4oCUCg==",
	"SW4gaGVyIHRvbWIgYnkgdGhlIHNvdW5kaW5nIHNlYS4K",
}

var encryptedStrings [][]byte

type KeyGuessesParams struct {
	posX, posY int
	guess      string
}

func init() {
	cph, err := aes.NewCipher(task3.RandByteArray(16))
	if err != nil {
		panic(err)
	}
	for _, b64str := range b64Strings {
		stream := cryptolabs.NewCTR(cph, 0)
		decodedStr, err := task1.DecodeBase64(b64str)
		if err != nil {
			panic(err)
		}
		decodedStr = bytes.Trim(decodedStr, "\n")
		encryptedString := make([]byte, len(decodedStr))
		stream.XORKeyStream(encryptedString, decodedStr)
		encryptedStrings = append(encryptedStrings, encryptedString)
	}
}

func maxLen(strings [][]byte) (ret int) {
	for _, v := range strings {
		if len(v) > ret {
			ret = len(v)
		}
	}
	return
}

func isAllAcceptableAt(pos int, keyElement byte, encryptedStrings [][]byte) bool {
	for _, v := range encryptedStrings {
		if len(v) <= pos {
			continue
		}
		char := rune(v[pos] ^ keyElement)
		if pos == 0 && !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZ", char) {
			return false
		} else if pos != 0 && !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,.!-();", char) {
			return false
		}
	}
	return true
}

func decryptStrings(keyStream []byte, bruted []bool, encryptedStrings [][]byte) (ret []string) {
	for _, v := range encryptedStrings {
		str := make([]byte, len(v))
		for i := 0; i < len(v); i++ {
			if !bruted[i] {
				str[i] = '#'
			} else {
				str[i] = keyStream[i] ^ v[i]
			}
		}
		ret = append(ret, string(str))
	}
	return
}

func extendKeyStream(keyStream, cipheredLine []byte, bruted []bool, pos int, guess string) {
	for i := 0; i < len(guess); i++ {
		keyStream[i+pos] = cipheredLine[i+pos] ^ byte(guess[i])
		bruted[i+pos] = true
	}
}

func MyKeyGuesses(keyStream []byte, encryptedStrings [][]byte, bruted []bool, guessParams []KeyGuessesParams) {
	for _, v := range guessParams {
		extendKeyStream(keyStream, encryptedStrings[v.posX], bruted, v.posY, v.guess)
	}
}

func BreakUsingSubsts() (ret []string) {
	maxKsLen := maxLen(encryptedStrings)
	keyStream := make([]byte, maxKsLen)
	bruted := make([]bool, maxKsLen)
	for i := 0; i < maxKsLen; i++ {
		for j := 0; j <= 0xFF; j++ {
			// check if all chars at position i is printable
			if isAllAcceptableAt(i, byte(j), encryptedStrings) {
				keyStream[i] = byte(j)
				bruted[i] = true
				break
			}
		}
	}
	guessParams := []KeyGuessesParams{
		{0, 4, "as many and many "},
		{3, 21, "l"},
		{1, 22, "a,"},
		{0, 1, "t"},
		{7, 24, "ea,"},
		{0, 27, " ago,"},
		{6, 32, "d"},
		{2, 33, "u "},
		{29, 35, "ove"},
		{10, 39, " Heave"},
		{4, 45, "ht"},
		{8, 47, "e—"},
	}
	MyKeyGuesses(keyStream, encryptedStrings, bruted, guessParams)
	return decryptStrings(keyStream, bruted, encryptedStrings)
}
