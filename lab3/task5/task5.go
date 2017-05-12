package task5

import (
	"bytes"
	"cryptolabs"
	"cryptolabs/lab1/task3"
	"cryptolabs/lab3/task4"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"
)

var Key []byte

const maxkeylen = 100

func init() {
	rand.Seed(time.Now().Unix())
	keyLen := rand.Intn(maxkeylen-1) + 1
	Key = task3.RandByteArray(keyLen)
	Key = []byte("testkey")
}

func SignMessage(msg []byte) (digest [20]byte) {
	return task4.Sha1Mac(Key, msg)
}

func CheckSignature(msg []byte, digest [20]byte) bool {
	return task4.CheckSha1Mac(Key, msg, digest)
}

func forgeMessage(keyLen int, msg, suffix []byte, digest [20]byte) (newMsg []byte, newDigest [20]byte) {
	h0 := binary.BigEndian.Uint32(digest[0:4])
	h1 := binary.BigEndian.Uint32(digest[4:8])
	h2 := binary.BigEndian.Uint32(digest[8:12])
	h3 := binary.BigEndian.Uint32(digest[12:16])
	h4 := binary.BigEndian.Uint32(digest[16:20])
	paddedMessage := cryptolabs.Sha1padding(append(bytes.Repeat([]byte{0}, keyLen), msg...))
	newMessage := append(paddedMessage, suffix...)
	paddedNewMessage := cryptolabs.Sha1padding(newMessage)
	fmt.Printf("%v\n%v\n", newMessage[keyLen:], paddedNewMessage[len(paddedMessage):])
	newDigest = cryptolabs.NewSHA1WithCustomOpts(paddedNewMessage[len(paddedMessage):], h0, h1, h2, h3, h4).Digest()
	return newMessage[keyLen:], newDigest
}

func AddSuffixAndResign(sourceMessage, suffix []byte, digest [20]byte) (newMsg []byte, newDigest [20]byte) {
	/*for i := 1; i <= maxkeylen; i++ {
		forgedMsg := forgeMessage(i, sourceMessage, suffix)
		if CheckSignature(forgedMsg) {
			return forgedMsg
		}
	}*/
	return forgeMessage(len(Key), sourceMessage, suffix, digest)
}
