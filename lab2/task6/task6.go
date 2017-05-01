package task6

import (
	"cryptolabs"
	"errors"
	"math/rand"
	"time"
)

func CreateSeed() uint32 {
	t := time.Now()
	rand.Seed(time.Now().Unix())
	return uint32(t.Add(time.Second * time.Duration(rand.Intn(1200-60)+60)).Unix())
}

func CrackSeed(prevTime, existingValue uint32) (uint32, error) {
	rand.Seed(time.Now().Unix())
	t := time.Unix(int64(prevTime), 0).Add(time.Second * time.Duration(rand.Intn(1200-60)+60))
	for i := uint32(60); i <= 1200; i++ {
		k := uint32(t.Unix()) - i
		var gen cryptolabs.MT19937
		gen.Seed(k)
		if existingValue == gen.Uint32() {
			return k, nil
		}
	}
	return 0, errors.New("seed crack error")
}
