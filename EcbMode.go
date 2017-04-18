package cryptolabs

import "crypto/cipher"

type transformFn func(dst []byte, src []byte)

type ecb struct {
	b         cipher.Block
	blockSize int
	fn        transformFn
}

func newECB(b cipher.Block, fn transformFn) ecb {
	return ecb{
		b:         b,
		blockSize: b.BlockSize(),
		fn:        fn,
	}
}

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return newECB(b, b.Encrypt)
}

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return newECB(b, b.Decrypt)
}

func (e ecb) BlockSize() int { return e.blockSize }

func (e ecb) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("ecb: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("ecb: output smaller than input")
	}

	for len(src) > 0 {
		e.fn(dst[:e.blockSize], src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}
