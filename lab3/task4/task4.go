package task4

import (
	"bytes"
	"cryptolabs"
)

func Sha1Mac(key, msg []byte) (digest [20]byte) {
	return cryptolabs.NewSHA1(append(key, msg...)).Digest()
}

func CheckSha1Mac(key, msg []byte, digest [20]byte) bool {
	actualDigest := cryptolabs.NewSHA1(append(key, msg...)).Digest()
	return bytes.Equal(digest[:], actualDigest[:])
}
