package cryptolabs

import (
	"encoding/binary"
)

type SHA1 struct {
	h0, h1, h2, h3, h4 uint32
}

func (s SHA1) sha1padding(msg []byte) (ret []byte) {
	sourceLength := uint64(len(msg))
	// stage 1 - pad to len(msg)%64 == 56
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

func (s SHA1) leftRotate(n uint32, shift uint) uint32 {
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
		temp := s.leftRotate(a, 5) + f + e + k + chunk[i]
		a, b, c, d, e = temp, a, s.leftRotate(b, 30), c, d
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

func NewSHA1(msg []byte) (ret SHA1) {
	ret.h0 = uint32(0x67452301)
	ret.h1 = uint32(0xEFCDAB89)
	ret.h2 = uint32(0x98BADCFE)
	ret.h3 = uint32(0x10325476)
	ret.h4 = uint32(0xC3D2E1F0)
	padded := ret.sha1padding(msg)
	for i := 0; i < len(msg); i += 64 {
		chunk := make([]uint32, 80)
		for j := 0; j < 16; j++ {
			chunk[j] = binary.BigEndian.Uint32(padded[i+j<<2 : i+(j+1)<<2])
		}
		for j := 16; j < len(chunk); j++ {
			chunk[j] = ret.leftRotate(chunk[j-3]^chunk[j-8]^chunk[j-14]^chunk[j-16], 1)
		}
		ret.handleChunk(chunk)
	}
	return
}
