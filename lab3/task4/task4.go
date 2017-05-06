package task4

import (
	"bytes"
	"cryptolabs"
)

func Sha1Mac(key, msg []byte) []byte {
	mac := cryptolabs.NewSHA1(append(key, msg...)).Digest()
	return append(mac[:], msg...)
}

func CheckSha1Mac(key, msgWithMac []byte) bool {
	if len(msgWithMac) < 20 {
		panic("invalid message length")
	}
	mac := msgWithMac[:20]
	payload := msgWithMac[20:]
	actualMac := cryptolabs.NewSHA1(append(key, payload...)).Digest()
	return bytes.Equal(mac, actualMac[:])
}
