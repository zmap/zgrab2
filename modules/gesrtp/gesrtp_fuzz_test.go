package gesrtp

import "testing"

// FuzzParseControllerTypeResponse ensures the parser never panics or reads
// out of bounds on arbitrary input.
func FuzzParseControllerTypeResponse(f *testing.F) {
	f.Add(makeControllerTypeResponse(svcReturnControllerType, 0x05, "RX3I"))
	f.Add(makeControllerTypeResponse(0xFF, 0x00, ""))
	f.Add(make([]byte, headerLen))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseControllerTypeResponse(data)
	})
}

// FuzzControllerTypePayloadLen ensures the header-length check never panics
// on arbitrary input.
func FuzzControllerTypePayloadLen(f *testing.F) {
	f.Add(make([]byte, headerLen))
	f.Add([]byte{})
	f.Add(make([]byte, headerLen-1))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = controllerTypePayloadLen(data)
	})
}

// FuzzValidateInitResponse ensures the Init-response check never panics on
// arbitrary input.
func FuzzValidateInitResponse(f *testing.F) {
	f.Add(makeInitResponse(true))
	f.Add(makeInitResponse(false))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = validateInitResponse(data)
	})
}
