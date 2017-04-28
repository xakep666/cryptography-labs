package lab2

import (
	"cryptolabs/lab2/task1"
	"fmt"
	"testing"
)

func TestTask1(t *testing.T) {
	cipherText, iv := task1.EncryptRandLineCBC()
	fmt.Printf("%s\n", task1.DecLine(iv, cipherText, task1.DecryptCBC))
}
