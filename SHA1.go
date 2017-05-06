package cryptolabs

import (
	"encoding/binary"
)

type SHA1 struct {
	h0, h1, h2, h3, h4 uint32
}

func (s SHA1) sha1padding(msg []byte, sourceLength uint64) (ret []byte) {
	if sourceLength == 0 {
		sourceLength = uint64(len(msg))
	}
	// stage 1 - pad to sourceLength%64 == 56
	bytesToAdd := (56 - len(msg)%64) % 64
	stage1padding := make([]byte, bytesToAdd)
	stage1padding[0] |= 1 << 7
	ret = append(msg, stage1padding...)
	// stage 2 - add source message length as big-endian uint64
	stage2padding := make([]byte, 8)
	binary.BigEndian.PutUint64(stage2padding, sourceLength<<3)
	ret = append(ret, stage2padding...)
	return
}

func leftRotate(n uint32, shift uint) uint32 {
	return (n << shift) | (n >> (32 - shift))
}

func (s *SHA1) handleChunk(chunk []uint32) {
	a := s.h0
	b := s.h1
	c := s.h2
	d := s.h3
	e := s.h4

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
		temp := leftRotate(a, 5) + f + e + k + chunk[i]
		a, b, c, d, e = temp, a, leftRotate(b, 30), c, d
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

func splitMessageToChunks(msg []byte) (chunks [][]uint32) {
	if len(msg)%64 != 0 {
		panic("message must be aligned to 64 items")
	}
	chunks = make([][]uint32, len(msg)/64)
	for i := 0; i < len(msg); i += 64 {
		chunks[i] = make([]uint32, 80)
		for j := 0; j < 16; j++ {
			chunks[i][j] = binary.BigEndian.Uint32(msg[i+j<<2 : i+(j+1)<<2])
		}
		for j := 16; j < len(chunks[i]); j++ {
			chunks[i][j] = leftRotate(chunks[i][j-3]^chunks[i][j-8]^chunks[i][j-14]^chunks[i][j-16], 1)
		}
	}
	return
}

func NewSHA1(msg []byte) (ret SHA1) {
	ret.h0 = uint32(0x67452301)
	ret.h1 = uint32(0xEFCDAB89)
	ret.h2 = uint32(0x98BADCFE)
	ret.h3 = uint32(0x10325476)
	ret.h4 = uint32(0xC3D2E1F0)
	padded := ret.sha1padding(msg, 0)
	for _, chunk := range splitMessageToChunks(padded) {
		ret.handleChunk(chunk)
	}
	return
}

func NewSHA1WithCustomOpts(msg []byte, h0, h1, h2, h3, h4 uint32, length uint64) (ret SHA1) {
	ret.h0, ret.h1, ret.h2, ret.h3, ret.h4 = h0, h1, h2, h3, h4
	padded := ret.sha1padding(msg, length)
	for _, chunk := range splitMessageToChunks(padded) {
		ret.handleChunk(chunk)
	}
	return
}
