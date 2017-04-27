package task6

import (
	"crypto/aes"
	"crypto/cipher"
	"cryptolabs"
	"cryptolabs/lab1/task1"
	"cryptolabs/lab1/task2"
	"cryptolabs/lab1/task3"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

const blkSize = 16

var ecbEnc, ecbDec cipher.BlockMode

func init() {
	key := task3.RandByteArray(blkSize)
	cph, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ecbEnc = cryptolabs.NewECBEncrypter(cph)
	ecbDec = cryptolabs.NewECBDecrypter(cph)
}

func urlParamsToMap(params string) map[string]string {
	fields := strings.Split(params, "&")
	ret := map[string]string{}
	for _, field := range fields {
		pair := strings.Split(field, "=")
		ret[pair[0]] = pair[1]
	}
	return ret
}

func mapToUrlParams(m map[string]string) (ret string) {
	for k, v := range m {
		ret += k + "=" + v + "&"
	}
	ret = strings.TrimSuffix(ret, "&")
	return ret
}

func ProfileFor(email string) string {
	rand.Seed(time.Now().Unix())
	if strings.ContainsAny(email, "&=") || !strings.ContainsAny(email, "@") {
		panic("invalid email address")
	}
	profile := "email=" + email + "&"
	profile += "uid=" + strconv.Itoa(rand.Intn(100)) + "&"
	profile += "role=user"
	return profile
}

func EncryptProfile(profile string) []byte {
	if strings.Contains(profile, "role=admin") {
		panic("cannot register as admin")
	}
	padded := task1.Pkcs7Pad([]byte(profile), ecbEnc.BlockSize())
	ret := make([]byte, len(padded))
	ecbEnc.CryptBlocks(ret, padded)
	return ret
}

func decryptProfile(cipherText []byte) string {
	ret := make([]byte, len(cipherText))
	ecbDec.CryptBlocks(ret, cipherText)
	unpadded, _ := task2.TrimPkcs7Pad(ret)
	return string(unpadded)
}

// pad email so role value only in last block
func SpecialPadEmail(profile string) string {
	m := urlParamsToMap(profile)
	email := strings.Split(m["email"], "@")
	name, domain := email[0], email[1]
	roleIndex := strings.LastIndex(profile, "user")
	newRoleIndex := (roleIndex/blkSize)*blkSize + blkSize
	padChrNum := newRoleIndex - roleIndex - 1
	if padChrNum == 0 {
		return profile
	}
	if padChrNum == 1 {
		padChrNum += blkSize
	}
	newMail := name + "+" + strings.Repeat("x", padChrNum) + "@" + domain
	return strings.Replace(profile, m["email"], newMail, 1)
}

func encryptRoleUsingProfile(role string, blkSize int) []byte {
	prefix := strings.Repeat("\xEA", blkSize-len("email="))
	padded := string(task1.Pkcs7Pad([]byte(role), blkSize))
	profile := ProfileFor(prefix + padded + "@test.com")
	encryptedRole := EncryptProfile(profile)[blkSize : 2*len(padded)]
	return encryptedRole
}

func ReplaceRoleInCipherText(cipherText []byte, role string) []byte {
	newRoleBlock := encryptRoleUsingProfile(role, blkSize)
	return append(cipherText[:len(cipherText)-blkSize], newRoleBlock...)
}

func DecryptAndPrintProfile(cipherText []byte) {
	fmt.Println(urlParamsToMap(decryptProfile(cipherText)))
}
