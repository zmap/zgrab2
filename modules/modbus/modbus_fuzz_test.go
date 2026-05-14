package modbus

import (
	"testing"
)

func FuzzParseMEIObject(f *testing.F) {
	// Seed: MEI object - object ID, length, value bytes
	f.Add([]byte{0x00, 0x03, 0x41, 0x42, 0x43})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseMEIObject(data)
	})
}

func FuzzGetMEIResponse(f *testing.F) {
	// Seed: MEI response data - MEI type (0x0E), conformity, more/follow, next OID, num objects, object data
	f.Add([]byte{0x0E, 0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 0x41, 0x42, 0x43}, true)
	f.Add([]byte{0x0E, 0x02, 0x01, 0x01, 0x00}, false)

	f.Fuzz(func(t *testing.T, data []byte, strict bool) {
		resp := &ModbusResponse{
			Function: 0x2B,
			Data:     data,
		}
		_, _ = resp.getMEIResponse(strict)
	})
}
