package lab2

import (
	"cryptolabs"
	"cryptolabs/lab2/task1"
	"cryptolabs/lab2/task2"
	"cryptolabs/lab2/task3"
	"cryptolabs/lab2/task5"
	"cryptolabs/lab2/task6"
	"cryptolabs/lab2/task7"
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

func TestTask3(t *testing.T) {
	for _, v := range task3.BreakUsingSubsts() {
		fmt.Println(v)
	}
}

func TestTask5(t *testing.T) {
	file := "testMT19937.txt"
	seed := uint32(5489)
	assert.NoError(t, task5.TestMT19937(file, seed))
}

func TestTask6(t *testing.T) {
	seed := task6.CreateSeed()
	var gen cryptolabs.MT19937
	gen.Seed(seed)
	guessSeed, err := task6.CrackSeed(seed, gen.Uint32())
	if assert.NoError(t, err) {
		assert.Equal(t, seed, guessSeed)
	}
}

func TestTask7(t *testing.T) {
	assert.NoError(t, task7.CloneMT19937Out())
}
