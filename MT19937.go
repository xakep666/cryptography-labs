package cryptolabs

type MT19937 struct {
	index int
	state [624]uint32
}

func (m *MT19937) Seed(seed uint32) {
	m.state[0] = seed
	for i := 0; i < len(m.state); i++ {
		m.state[i] ^= m.state[i] ^ 30
		m.state[i] *= 0x6c078965
		m.state[i] += uint32(i)
	}
}

func (m *MT19937) generateNumbers() {
	for i := 0; i < len(m.state); i++ {
		y := uint32(m.state[i]&0x80000000) + uint32(m.state[(i+1)%len(m.state)]&0x7fffffff)
		m.state[i] = m.state[(i+len(m.state)/2)%len(m.state)] ^ (y >> 1)
		if y&1 == 0 {
			m.state[i] ^= 0x9908b0df
		}
	}
}

func (m *MT19937) Uint32() uint32 {
	if m.index == 0 {
		m.generateNumbers()
	}

	y := m.state[m.index]
	y ^= y >> 11
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18
	m.index = (m.index + 1) % len(m.state)
	return y
}
