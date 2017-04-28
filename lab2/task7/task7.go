package task7

import (
	"cryptolabs"
	"errors"
	"time"
)

func getMSB(x uint32, n uint) uint32 {
	if n < 0 {
		return 0
	}
	return (x >> (31 - n)) & 1
}

func setMSB(x uint32, n uint, bit uint32) uint32 {
	return x | (bit << (31 - n))
}

func undoRightShiftXor(y uint32, s uint) uint32 {
	z := uint32(0)
	for i := uint(0); i < 32; i++ {
		z = setMSB(z, i, getMSB(y, i)^getMSB(z, i-s))
	}
	return z
}

func getLSB(x uint32, n uint) uint32 {
	if n < 0 {
		return 0
	}
	return (x >> n) & 1
}

func setLSB(x uint32, n uint, bit uint32) uint32 {
	return x | (bit << n)
}

func undoLeftShiftXorAnd(y uint32, s uint, k uint32) uint32 {
	z := uint32(0)
	for i := uint(0); i < 32; i++ {
		z = setLSB(z, i, getLSB(y, i)^(getLSB(z, i-s)&getLSB(k, i)))
	}
	return z
}

func untemper(y uint32) uint32 {
	y = undoRightShiftXor(y, 18)
	y = undoLeftShiftXorAnd(y, 15, 0xefc60000)
	y = undoLeftShiftXorAnd(y, 7, 0x9d2c5680)
	y = undoRightShiftXor(y, 11)
	return y
}

func CloneMT19937Out() error {
	var gen, gen2 cryptolabs.MT19937
	seed := uint32(time.Now().Unix())
	gen.Seed(seed)
	var myState [624]uint32
	for i := 0; i < len(myState); i++ {
		myState[i] = untemper(gen.Uint32())
	}
	gen2.State = myState

	for i := 0; i < 1000; i++ {
		source := gen.Uint32()
		cloned := gen2.Uint32()
		if source != cloned {
			return errors.New("cloning error")
		}
	}
	return nil
}
