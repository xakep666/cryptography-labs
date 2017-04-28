package task2

import (
	"crypto/aes"
	"cryptolabs"
	"cryptolabs/lab0/task1"
)

func CTRDecryptB64Line(b64line string, key []byte, nonce uint64) (string, error) {
	cph, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	stream := cryptolabs.NewCTR(cph, nonce)
	data, err := task1.DecodeBase64(b64line)
	ret := make([]byte, len(data))
	stream.XORKeyStream(ret, data)
	return string(ret), nil
}
