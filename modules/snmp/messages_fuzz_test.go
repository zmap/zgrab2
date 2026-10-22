package snmp

import "testing"

func FuzzDecodeOID(f *testing.F) {
	for _, seed := range [][]byte{
		{0x2b},
		{0x2b, 0x06, 0x01, 0x02, 0x01},
		{0x81, 0x34, 0x03},
		{0x2b, 0x80},
		{},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		oid, err := decodeOID(data)
		if err != nil {
			return
		}
		encoded, err := encodeOID(oid)
		if err != nil {
			t.Fatalf("encodeOID(%q) failed after successful decode: %v", oid, err)
		}
		decoded, err := decodeOID(encoded)
		if err != nil || decoded != oid {
			t.Fatalf("OID round trip failed: decoded=%q err=%v", decoded, err)
		}
	})
}

func FuzzParseResponse(f *testing.F) {
	f.Add(buildTestResponse("1"))
	f.Add(buildTestResponse("2c"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseResponse(data)
		_, _ = ParseV3DiscoveryResponse(data)
	})
}
