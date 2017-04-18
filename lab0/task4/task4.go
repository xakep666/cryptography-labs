package task4

import (
	"cryptolabs/lab0/task3"
	"fmt"
	"io"
	"os"
)

func FindSingleXorStr(path string, bfKeys string) (str string, key byte, lineNum int, err error) {
	file, err := os.Open(path)
	defer file.Close()
	if err != nil {
		return
	}
	line := ""
	_, err = fmt.Fscanln(file, &line)
	maxScore := 0.
	for i := 1; err != io.EOF; i++ {
		iterStr, iterKey, bfErr := task3.BruteForceOneByteXor([]byte(line), bfKeys)
		if bfErr != nil {
			return
		}
		score := task3.GetFreqScore(iterStr)
		if score > maxScore {
			maxScore = score
			lineNum = i
			key = iterKey
			str = iterStr
		}
		_, err = fmt.Fscanln(file, &line)
	}
	err = nil
	return
}
