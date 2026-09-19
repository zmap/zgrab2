package msmq

import "testing"

// FuzzParseEstablishConnection ensures the parser never panics or reads out
// of bounds on arbitrary input.
func FuzzParseEstablishConnection(f *testing.F) {
	var clientGUID, serverGUID [16]byte
	f.Add(makeEstablishConnectionResponse(clientGUID, serverGUID, 0, false, responsePaddingByte))
	f.Add(makeEstablishConnectionResponse(clientGUID, serverGUID, 0xFFFFFFFF, true, responsePaddingByte))
	f.Add([]byte{})
	f.Add(make([]byte, establishConnectionPacketLen-1))
	// Length prefix/version look right, but everything else is truncated.
	f.Add([]byte{baseHeaderVersion, 0, 0, 0x10})

	f.Fuzz(func(t *testing.T, data []byte) {
		if res, err := parseEstablishConnection(data); err == nil {
			_ = formatGUID(res.ClientGUID)
			_ = formatGUID(res.ServerGUID)
		}
	})
}
