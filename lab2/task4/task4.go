package task4

import (
	"cryptolabs/lab0/task1"
	"cryptolabs/lab0/task3"
	"cryptolabs/lab0/task5"
	"fmt"
	"io"
	"os"
	"strings"
)

func LoadDataFromFile(path string) (ret [][]byte, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	line := ""
	for _, err := fmt.Fscanln(file, &line); err == nil; _, err = fmt.Fscanln(file, &line) {
		var data []byte
		data, err = task1.DecodeBase64(line)
		ret = append(ret, data)
	}
	if err == io.EOF {
		err = nil
	}
	return
}

func minLineLen(lines [][]byte) (ret int) {
	ret = 0xFFFFFFF
	for _, v := range lines {
		if len(v) < ret {
			ret = len(v)
		}
	}
	return
}

func PreProcessLines(lines [][]byte) (ret []byte, keyLen int) {
	keyLen = minLineLen(lines)
	for _, v := range lines {
		ret = append(ret, v[:keyLen]...)
	}
	return
}

func SplitLines(lines []byte, lineLen int) (ret [][]byte) {
	for i := 0; i < len(lines); i += lineLen {
		tmp := make([]byte, lineLen)
		copy(tmp, lines[i:i+lineLen])
		ret = append(ret, tmp)
	}
	return
}

func isAllAcceptableAt(pos, keyLen int, keyElement byte, line []byte) bool {
	for i := 0; i < len(line)/keyLen; i++ {
		char := rune(line[i*keyLen+pos] ^ keyElement)
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,.!-();", char) {
			return false
		}
	}
	return true
}

func decryptLine(key []byte, bruted []bool, line []byte) (ret []byte) {
	ret = make([]byte, len(line))
	for k, v := range key {
		for i := 0; i < len(line)/len(key); i++ {
			if !bruted[k] {
				ret[i*len(key)+k] = '#'
			} else {
				ret[i*len(key)+k] = v ^ line[i*len(key)+k]
			}
		}
	}
	return
}

func BreakRepeatedKeyXor(line []byte, keyLen int) (ret []byte) {
	key := make([]byte, keyLen)
	bruted := make([]bool, keyLen)
	for i := 0; i < keyLen; i++ {
		var iterLine []byte
		for j := 0; j < len(line)/keyLen; j++ {
			iterLine = append(iterLine, line[j*keyLen+i])
		}
		var maxScore float64
		var maxScoreKeyElement byte
		for j := 0; j <= 0xFF; j++ {
			decr := task5.XorRepitiveKey(iterLine, []byte{byte(j)})
			score := task3.GetFreqScore(string(decr))
			if score > maxScore {
				maxScore = score
				maxScoreKeyElement = byte(j)
			}
		}
		bruted[i] = true
		key[i] = maxScoreKeyElement
	}

	// key correction
	// without this first line is "onCe Upon A mIDnIght dreARy"
	firstStr := "Once upon a midnight dreary"
	for i := 0; i < len(firstStr); i++ {
		key[i] = firstStr[i] ^ line[i]
	}

	return decryptLine(key, bruted, line)
}
