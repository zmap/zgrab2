package snmp

import "testing"

func TestOIDRoundTrip(t *testing.T) {
	for _, oid := range []string{
		"0.0",
		"1.3.6.1.2.1.1.1.0",
		"2.40.3",
		"2.999.123456",
	} {
		t.Run(oid, func(t *testing.T) {
			encoded, err := encodeOID(oid)
			if err != nil {
				t.Fatalf("encodeOID() error = %v", err)
			}
			decoded, err := decodeOID(encoded)
			if err != nil {
				t.Fatalf("decodeOID() error = %v", err)
			}
			if decoded != oid {
				t.Fatalf("decodeOID(encodeOID(%q)) = %q", oid, decoded)
			}
		})
	}
}

func TestDecodeOIDRejectsUnterminatedSubidentifier(t *testing.T) {
	for _, encoded := range [][]byte{
		{0x2b, 0x80},
		{0x2b, 0x81},
		{0x2b, 0x81, 0x80},
	} {
		if _, err := decodeOID(encoded); err == nil {
			t.Fatalf("decodeOID(%x) unexpectedly succeeded", encoded)
		}
	}
}

func TestEncodeOIDValidatesFirstArcs(t *testing.T) {
	for _, oid := range []string{"3.0", "0.40", "1.40"} {
		if _, err := encodeOID(oid); err == nil {
			t.Fatalf("encodeOID(%q) unexpectedly succeeded", oid)
		}
	}
}
