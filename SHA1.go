package cryptolabs

import (
	"encoding/binary"
)

type SHA1 struct {
	h0, h1, h2, h3, h4 uint32
}

func Sha1padding(msg []byte) []byte {
	sourceLength := uint64(len(msg))
	padded := make([]byte, sourceLength+63&^(sourceLength&63)+1)
	copy(padded[:sourceLength], msg)
	padded[sourceLength] = 0x80
	binary.BigEndian.PutUint64(padded[len(padded)-8:], sourceLength<<3)
	return padded
}

func LeftRotate(n uint32, shift uint) uint32 {
	return (n << shift) | (n >> (32 - shift))
}

func (s *SHA1) handleChunk(chunk []uint32) {
	a, b, c, d, e := s.h0, s.h1, s.h2, s.h3, s.h4

	for i := 0; i < len(chunk); i++ {
		var f, k uint32
		switch {
		case i >= 0 && i <= 19:
			f, k = d^(b&(c^d)), 0x5a827999
		case i >= 20 && i <= 39:
			f, k = b^c^d, 0x6ed9eba1
		case i >= 40 && i <= 59:
			f, k = (b&c)|(d&(b|c)), 0x8f1bbcdc
		case i >= 60 && i <= 79:
			f, k = b^c^d, 0xca62c1d6
		}
		temp := LeftRotate(a, 5) + f + e + k + chunk[i]
		a, b, c, d, e = temp, a, LeftRotate(b, 30), c, d
	}

	s.h0 += a
	s.h1 += b
	s.h2 += c
	s.h3 += d
	s.h4 += e
}

func (s SHA1) Digest() (ret [20]byte) {
	binary.BigEndian.PutUint32(ret[0:4], s.h0)
	binary.BigEndian.PutUint32(ret[4:8], s.h1)
	binary.BigEndian.PutUint32(ret[8:12], s.h2)
	binary.BigEndian.PutUint32(ret[12:16], s.h3)
	binary.BigEndian.PutUint32(ret[16:20], s.h4)
	return
}

func (s SHA1) splitMessageToChunks(msg []byte) <-chan []uint32 {
	if len(msg)&63 != 0 {
		panic("message must be aligned to 64 items")
	}
	chunks := make(chan []uint32)
	go func() {
		for i := 0; i < len(msg)/64; i++ {
			chunk := make([]uint32, 80)
			for j := 0; j < 16; j++ {
				chunk[j] = binary.BigEndian.Uint32(msg[i+j<<2 : i+(j+1)<<2])
			}
			for j := 16; j < len(chunk); j++ {
				chunk[j] = LeftRotate(chunk[j-3]^chunk[j-8]^chunk[j-14]^chunk[j-16], 1)
			}
			chunks <- chunk
		}
		close(chunks)
	}()
	return chunks
}

func NewSHA1(msg []byte) *SHA1 {
	ret := &SHA1{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	for chunk := range ret.splitMessageToChunks(Sha1padding(msg)) {
		ret.handleChunk(chunk)
	}
	return ret
}

func NewSHA1WithCustomOpts(padded []byte, h0, h1, h2, h3, h4 uint32) *SHA1 {
	ret := &SHA1{h0, h1, h2, h3, h4}
	for chunk := range ret.splitMessageToChunks(padded) {
		ret.handleChunk(chunk)
	}
	return ret
}
