package task5

import (
	"cryptolabs"
	"errors"
	"fmt"
	"os"
	"strconv"
)

func readNumbers(path string) (ret []uint32, err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	line := ""
	for _, err := fmt.Fscanln(file, &line); err != nil; _, err = fmt.Fscanln(file, &line) {
		num := 0
		num, err = strconv.Atoi(line)
		ret = append(ret, uint32(num))
	}
	return ret, nil
}

func TestMT19937(testSetFile string, seed uint32) error {
	testSet, err := readNumbers(testSetFile)
	if err != nil {
		return err
	}
	var gen cryptolabs.MT19937
	gen.Seed(seed)
	for k, v := range testSet {
		generated := gen.Uint32()
		if generated != v {
			return errors.New(fmt.Sprintf("iteration %d\nexpected %u got %u\n", k, v, generated))
		}
	}
	return nil
}
