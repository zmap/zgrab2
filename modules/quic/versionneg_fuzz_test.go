package quic

import "testing"

// FuzzParseVersionNegotiation ensures the parser never panics or reads out of
// bounds on arbitrary input.
func FuzzParseVersionNegotiation(f *testing.F) {
	f.Add(makeVersionNegotiation([]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9}, 0x00000001, 0x6b3343cf))
	f.Add(makeVersionNegotiation(nil, nil, 0xff00001d))
	f.Add(buildVersionProbe(probeVersion, []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}))
	f.Add([]byte{})
	f.Add([]byte{0x80, 0, 0, 0, 0, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		vn, err := parseVersionNegotiation(data)
		if err != nil {
			return
		}
		if len(vn.Versions) == 0 {
			t.Fatal("parsed a version negotiation packet without versions")
		}
		for _, v := range vn.Versions {
			_ = newVersion(v)
		}
	})
}
