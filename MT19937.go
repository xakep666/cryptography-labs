package cryptolabs

type MT19937 struct {
	index int
	State [624]uint32
}

func (m *MT19937) Seed(seed uint32) {
	m.State[0] = seed
	for i := 1; i < len(m.State); i++ {
		m.State[i] = m.State[i-1] ^ (m.State[i-1] >> 30)
		m.State[i] *= 0x6c078965
		m.State[i] += uint32(i)
	}
}

func (m *MT19937) generateNumbers() {
	for i := 0; i < len(m.State); i++ {
		y := uint32(m.State[i]&0x80000000) + uint32(m.State[(i+1)%len(m.State)]&0x7fffffff)
		m.State[i] = m.State[(i+len(m.State)/2)%len(m.State)] ^ (y >> 1)
		if y&1 == 0 {
			m.State[i] ^= 0x9908b0df
		}
	}
}

func (m *MT19937) Uint32() uint32 {
	if m.index == 0 {
		m.generateNumbers()
	}

	y := m.State[m.index]
	y ^= y >> 11
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= y >> 18
	m.index = (m.index + 1) % len(m.State)
	return y
}
