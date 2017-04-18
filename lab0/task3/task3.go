package task3

import (
	"math"
	"strings"
	"unicode"
)

// a - z (percents)
var charFreqsEthalon = []float64{8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074}

const maxNonPrintableFreq = 6.5 // percents
const filterChars = "*#@$"

func GetFreqScore(str string) (ret float64) {
	str = strings.ToLower(str)
	charFreqs := make([]float64, len(charFreqsEthalon))
	letters := float64(0)
	for _, chr := range str {
		if (chr <= 'z') && (chr >= 'a') {
			charFreqs[chr-'a']++
			letters++
		}
	}
	for i := 0; i < len(charFreqs); i++ {
		charFreqs[i] /= letters
		ret += math.Abs(math.Log2(math.Abs(charFreqs[i] - charFreqsEthalon[i]/100)))
	}
	return
}

func OneByteXor(buf []byte, key byte) []byte {
	ret := make([]byte, len(buf))
	copy(ret, buf)
	for i := 0; i < len(buf); i++ {
		ret[i] ^= key
	}
	return ret
}

func BruteForceOneByteXor(bytes []byte, alph string) (string, byte, error) {
	maxScore := 0.
	key := byte(0)
	decodedStr := ""
	for _, i := range alph {
		str := string(OneByteXor(bytes, byte(i)))
		if strings.ContainsAny(str, filterChars) {
			continue
		}
		nonPrintable := 0.
		for _, chr := range str {
			if !unicode.IsPrint(rune(chr)) {
				nonPrintable++
			}
		}
		if nonPrintable/float64(len(str)) > maxNonPrintableFreq/100. {
			continue
		}
		score := GetFreqScore(str)
		if score > maxScore {
			key = byte(i)
			decodedStr = str
			maxScore = score
		}
	}
	return decodedStr, key, nil
}
