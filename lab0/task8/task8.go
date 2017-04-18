package task8

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

type uint128 struct {
	high, low uint64
}

func readHexLinesFromFile(path string) (ret [][]byte, err error) {
	file, err := os.Open(path)
	line := ""
	for _, err := fmt.Fscanln(file, &line); err != io.EOF; _, err = fmt.Fscanln(file, &line) {
		bytes, err := hex.DecodeString(line)
		if err != nil {
			return ret, err
		}
		ret = append(ret, bytes)
	}
	return
}

func count16ByteBlocks(source []byte) map[uint128]int {
	block := uint128{low: 0, high: 0}
	ret := make(map[uint128]int)
	for i := 0; i < len(source); i++ {
		if i&0xF == 0 && i != 0 {
			ret[block]++
			block = uint128{low: 0, high: 0}
		}
		if i&0xF < 8 {
			block.high |= uint64(source[i]) << uint((i&0xF)<<3)
		} else {
			block.low |= uint64(source[i]) << uint((i&0xF-8)<<3)
		}
	}
	return ret
}

const blockRepeatThreshold = 2

func FindPossibleEcb(path string) error {
	byteLines, err := readHexLinesFromFile(path)
	if err != nil {
		return err
	}
	for idx, byteLine := range byteLines {
		blockMap := count16ByteBlocks(byteLine)
		for block, blockCount := range blockMap {
			if blockCount >= blockRepeatThreshold {
				highPart := make([]byte, 8)
				lowPart := make([]byte, 8)
				binary.LittleEndian.PutUint64(highPart, block.high)
				binary.LittleEndian.PutUint64(lowPart, block.low)
				fmt.Printf("line %d; block %s%s; repeats %d times; %v", idx+1,
					hex.EncodeToString(highPart), hex.EncodeToString(lowPart), blockCount, byteLine)
			}
		}
	}
	return nil
}
