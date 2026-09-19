package msrpc

import "testing"

// FuzzParseCommonHeader ensures the header parser never panics or reads out
// of bounds on arbitrary input.
func FuzzParseCommonHeader(f *testing.F) {
	f.Add(makeBindAck(1, 4280, 4280, 0, "", resultAcceptance, 0, [16]byte{}, 2, 0))
	f.Add(makeBindNak(1, 1))
	f.Add([]byte{})
	f.Add([]byte{5, 0, 12, 3})
	f.Add([]byte{5, 0, 12, 3, 0x10, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		hdr, err := parseCommonHeader(data)
		if err != nil || hdr == nil {
			return
		}
		if int(hdr.FragLength) > len(data) {
			return
		}
		full := data[:hdr.FragLength]
		switch hdr.PType {
		case ptypeBindAck:
			_, _ = parseBindAck(full)
		case ptypeBindNak:
			_, _ = parseBindNak(full)
		}
	})
}

// FuzzParseUUID ensures the UUID parser never panics on arbitrary input.
func FuzzParseUUID(f *testing.F) {
	f.Add(EPMUUID)
	f.Add(ndrUUID)
	f.Add("")
	f.Add("not-a-uuid")
	f.Add("e1af8308-5d1f-11c9-91a4-08002b14a0f")

	f.Fuzz(func(t *testing.T, s string) {
		if wire, err := parseUUID(s); err == nil {
			_ = formatUUID(wire[:])
		}
	})
}
