package task6

import (
	"cryptolabs"
	"errors"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().Unix())
}

func randTimeDelay(start, stop int) int {
	return rand.Intn(stop-start) + start
}

func CreateSeed() (uint32, time.Time) {
	t := time.Now()
	t = t.Add(time.Second * time.Duration(randTimeDelay(60, 1200)))
	return uint32(t.Unix()), t
}

func CrackSeed(prevTime time.Time, existingValue uint32) (uint32, error) {
	rand.Seed(time.Now().Unix())
	t := prevTime.Add(time.Second * time.Duration(randTimeDelay(60, 1200)))
	for i := 60; i <= 1200; i++ {
		k := t.Add(-time.Second * time.Duration(i))
		gen := new(cryptolabs.MT19937)
		gen.Seed(uint32(k.Unix()))
		if existingValue == gen.Uint32() {
			return uint32(k.Unix()), nil
		}
	}
	return 0, errors.New("seed crack error")
}
