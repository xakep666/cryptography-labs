package task7

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"net/http"
	"time"
)

func isValidSignature(message []byte, signature []byte, urlFormat string) (bool, time.Duration) {
	request := fmt.Sprintf(urlFormat, message, signature)
	start := time.Now()
	resp, err := http.Get(request)
	end := time.Now()
	defer resp.Body.Close()
	if err != nil {
		return false, 0
	}
	if resp.StatusCode == 200 {
		return true, end.Sub(start)
	}
	return false, end.Sub(start)
}

func guessNextByte(message, knownBytes []byte, delay time.Duration, urlFormat string) []byte {
	suffixLen := sha1.Size - len(knownBytes)
	_, baseDelay := isValidSignature(message, bytes.Repeat([]byte{0}, sha1.Size), urlFormat)
	expectedDuration := time.Duration(delay.Nanoseconds()*int64(len(knownBytes))) + 15*baseDelay
	start := time.Now()
	for i := 0; i < 0xFF; i++ {
		suffix := make([]byte, suffixLen)
		suffix[0] = byte(i)
		valid, duration := isValidSignature(message, append(knownBytes, suffix...), urlFormat)
		if valid {
			return append(knownBytes, suffix...)
		}
		if duration > expectedDuration {
			end := time.Now()
			fmt.Printf("Guessed byte 0x%X in %v, rps %.2f, max rps %.2f\n", i, end.Sub(start), float64(i)/end.Sub(start).Seconds(), float64(i)/expectedDuration.Seconds())
			return append(knownBytes, byte(i))
		}
	}
	panic("we should not be here")
	return nil
}

func CalculateHmac(message []byte, urlFormat string) (ret [sha1.Size]byte) {
	var knownBytes []byte
	for i := byte(0); i < sha1.Size; i++ {
		knownBytes = guessNextByte(message, knownBytes, Delay, urlFormat)
	}
	copy(ret[:], knownBytes)
	return
}
