package lab2

import (
	"cryptolabs/lab2/task1"
	"cryptolabs/lab2/task2"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTask1(t *testing.T) {
	cipherText, iv := task1.EncryptRandLineCBC()
	fmt.Printf("%s\n", task1.DecLine(iv, cipherText, task1.DecryptCBC))
}

func TestTask2(t *testing.T) {
	line := "Or6kII/NM5bDyWwvTGC3B6KFCPz9H2Cxvakxs/uGFmENxPykZx4XJqb62VPGj6rj7w=="
	key := []byte("YELLOW SUBMARINE")
	out, err := task2.CTRDecryptB64Line(line, key, 0)
	if assert.NoError(t, err) {
		fmt.Println(out)
	}
}
