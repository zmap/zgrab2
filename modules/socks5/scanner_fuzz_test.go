package socks5

import (
	"testing"
)

func FuzzExplainResponse(f *testing.F) {
	// Seed: SOCKS5 success response - version, status, reserved, addr type, IPv4 addr, port
	f.Add([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = explainResponse(data)
	})
}
