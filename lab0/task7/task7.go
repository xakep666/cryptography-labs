package task7

import (
	"cryptolabs/lab0/task6"
	"errors"
	"github.com/spacemonkeygo/openssl"
)

func DecryptWithCipher(source, key, iv []byte, cipher *openssl.Cipher) ([]byte, error) {
	ctx, err := openssl.NewDecryptionCipherCtx(cipher, nil, key, iv)
	if err != nil {
		return nil, err
	}
	cipherBytes, err := ctx.DecryptUpdate(source)
	if err != nil {
		return nil, err
	}
	finalBytes, err := ctx.DecryptFinal()
	if err != nil {
		return nil, err
	}
	ret := append(cipherBytes, finalBytes...)
	return ret, nil

}

func DecryptBase64File(path string, password string) ([]byte, error) {
	bytes, err := task6.Base64FromFile(path)
	if err != nil {
		return nil, err
	}
	header := bytes[0:8] // Salted__
	if string(header) != "Salted__" {
		return nil, errors.New("Salted__ header not found")
	}
	salt := bytes[8:16]
	payload := bytes[16:]
	cipher, err := openssl.GetCipherByName("aes-128-ecb")
	if err != nil {
		return nil, err
	}
	digest, err := openssl.GetDigestByNid(openssl.NID_md5)
	if err != nil {
		return nil, err
	}
	key, _, err := openssl.DeriveKey(cipher, digest, salt, []byte(password), 1)
	if err != nil {
		return nil, err
	}
	return DecryptWithCipher(payload, key, nil, cipher)
}
