package cryptolabs

import (
	"crypto/cipher"
	"encoding/binary"
)

// standard ctr has other round key format
type ctr struct {
	b cipher.Block
	//roundKey[0:8] is little-endian nonce, roundKey[8:16] is little-endian counter
	nonce   []byte
	counter uint64
}

func NewCTR(b cipher.Block, nonce uint64) cipher.Stream {
	if b.BlockSize() != 16 {
		panic("ctr: only 128bit blocks implemented")
	}
	ret := ctr{b: b, counter: 0}
	ret.nonce = make([]byte, b.BlockSize()/2)
	binary.LittleEndian.PutUint64(ret.nonce, nonce)
	return &ret
}

func (c *ctr) stateToRoundKey() []byte {
	counterArr := make([]byte, c.b.BlockSize()/2)
	binary.LittleEndian.PutUint64(counterArr, c.counter)
	state := append(c.nonce, counterArr...)
	ret := make([]byte, c.b.BlockSize())
	c.b.Encrypt(ret, state)
	return ret
}

func (c *ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("ctr: output smaller than input")
	}

	for len(src) >= c.b.BlockSize() {
		key := c.stateToRoundKey()
		for k, v := range src[:c.b.BlockSize()] {
			dst[k] = key[k] ^ v
		}
		dst = dst[c.b.BlockSize():]
		src = src[c.b.BlockSize():]
		c.counter++
	}
	// process remaining bytes
	key := c.stateToRoundKey()
	for k, v := range src {
		dst[k] = key[k] ^ v
	}
}
