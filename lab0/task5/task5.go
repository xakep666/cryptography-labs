package task5

func XorRepitiveKey(src, keyPart []byte) []byte {
	ret := make([]byte, len(src))
	for i := 0; i < len(src); i++ {
		ret[i] = src[i] ^ keyPart[i%len(keyPart)]
	}
	return ret
}
