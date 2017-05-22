package task8

import (
	"crypto/sha1"
	"cryptolabs/lab3/task7"
	"fmt"
	"time"
)

func guessNextByte(message string, knownBytes []byte, delay time.Duration, urlFormat string) []byte {
	suffixLen := sha1.Size - len(knownBytes)
	start := time.Now()
	durations := make([]time.Duration, 256)
	count := 10
	for i := 0; i < count; i++ {
		for j := range durations {
			suffix := make([]byte, suffixLen)
			suffix[0] = byte(j)
			_, duration := task7.IsValidSignature(message, append(knownBytes, suffix...), urlFormat)
			durations[j] += duration
		}
	}
	end := time.Now()
	fmt.Printf("Made %d requests in %v, rps %.2f\n", count*256, end.Sub(start), float64(count*256)/end.Sub(start).Seconds())

	for i := range durations {
		durations[i] = time.Duration(durations[i].Nanoseconds() / int64(count))
	}
	avgDuration := time.Duration(0)
	maxDuration := time.Duration(0)
	idx := 0
	for i := range durations {
		avgDuration += durations[i]
		if durations[i] > maxDuration {
			maxDuration = durations[i]
			idx = i
		}
	}
	avgDuration = time.Duration(avgDuration.Nanoseconds() / 256)
	fmt.Printf("Average duration %v, maximum duration %v at %d\n", avgDuration, maxDuration, idx)
	if maxDuration > avgDuration+time.Duration(float64(delay)*0.8) {
		return append(knownBytes, byte(idx))
	}
	return knownBytes[:len(knownBytes)-1]
}

func CalculateHmac(message string, urlFormat string, delay time.Duration) (ret [sha1.Size]byte) {
	var knownBytes []byte
	for {
		if len(knownBytes) == 20 {
			if valid, _ := task7.IsValidSignature(message, knownBytes, urlFormat); valid {
				break
			} else {
				knownBytes = knownBytes[:len(knownBytes)-1]
			}
		}
		knownBytes = guessNextByte(message, knownBytes, delay, urlFormat)
		fmt.Printf("Guessed bytes % X\n", knownBytes)
	}
	copy(ret[:], knownBytes)
	return
}
