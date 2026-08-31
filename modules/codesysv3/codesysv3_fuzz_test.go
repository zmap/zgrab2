package codesysv3

import (
	"encoding/binary"
	"testing"
)

func FuzzParseResponse(f *testing.F) {
	f.Add(buildFakeIdentificationResponse())
	f.Add([]byte{})
	f.Add([]byte{nsMagic})

	resp := buildFakeIdentificationResponse()
	framed := make([]byte, 8, 8+len(resp))
	binary.LittleEndian.PutUint32(framed[0:4], tcpBDMagic)
	binary.LittleEndian.PutUint32(framed[4:8], uint32(8+len(resp)))
	framed = append(framed, resp...)
	f.Add(framed)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseResponse(data)
	})
}
