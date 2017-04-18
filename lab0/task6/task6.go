package task6

import (
	"cryptolabs/lab0/task3"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
)

func Base64FromFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return []byte{}, err
	}
	defer file.Close()
	b64Reader := base64.NewDecoder(base64.StdEncoding, file)
	return ioutil.ReadAll(b64Reader)
}

func generateStringSet(source []byte, keyLen int) [][]byte {
	ret := make([][]byte, keyLen)
	for idx, chr := range source {
		ret[idx%keyLen] = append(ret[idx%keyLen], chr)
	}
	return ret
}

func BruteForceBase64Encoded(path string, bfKeys string) error {
	source, err := Base64FromFile(path)
	if err != nil {
		return err
	}
	for keyLen := 2; keyLen <= 40; keyLen++ {
		strSet := generateStringSet(source, keyLen)
		decStrs := make([]string, keyLen)
		maxLen := 0
		key := ""
		for idx, subStr := range strSet {
			decStr, ch, _ := task3.BruteForceOneByteXor(subStr, bfKeys)
			decStrs[idx] = decStr
			if maxLen < len(decStr) {
				maxLen = len(decStr)
			}
			key += string(ch)
		}
		outStr := ""
		for i := 0; i < maxLen; i++ {
			for j := 0; j < len(decStrs); j++ {
				if len(decStrs[j]) > i {
					outStr += string(decStrs[j][i])
				}
			}
		}
		fmt.Printf("key %s\n%s\n#########\n", key, outStr)
	}
	return nil
}
