package ipp

import "testing"

func FuzzReadAllAttributes(f *testing.F) {
	f.Add([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03})
	f.Add([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		scanner := &Scanner{
			config: &Flags{MaxSize: 256},
		}
		_, _ = readAllAttributes(data, scanner)
	})
}
