package bacnet

import "testing"

func FuzzReadInstanceNumber(f *testing.F) {
	// Seed: valid instance number encoding
	// Tag 0x0C (context-specific tag 0, length 4), followed by 4 bytes of instance number
	f.Add([]byte{0x0C, 0x00, 0x00, 0x00, 0x01})
	f.Add([]byte{0x0C, 0x00, 0x00, 0x00, 0xFF})
	f.Add([]byte{0x0C, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x0C, 0x00, 0x00, 0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		readInstanceNumber(data)
	})
}

func FuzzReadVendorID(f *testing.F) {
	// Seed: valid vendor ID encoding
	// Tag 0x78 (context-specific tag 7, length 2), followed by 2 bytes of vendor ID
	f.Add([]byte{0x78, 0x00, 0x00})
	f.Add([]byte{0x78, 0x00, 0x01})
	f.Add([]byte{0x78, 0xFF, 0xFF})
	f.Add([]byte{0x78, 0x01, 0x23})

	f.Fuzz(func(t *testing.T, data []byte) {
		readVendorID(data)
	})
}

func FuzzReadStringProperty(f *testing.F) {
	// Seed: valid string property encoding
	// Character string tag (application tag 7), encoding byte, then string data
	f.Add([]byte{0x75, 0x00, 0x68, 0x65, 0x6C, 0x6C, 0x6F}) // "hello" in UTF-8
	f.Add([]byte{0x71, 0x00})                                 // empty string
	f.Add([]byte{0x72, 0x00, 0x41})                           // "A"
	f.Add([]byte{0x76, 0x00, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x67}) // "testing"

	f.Fuzz(func(t *testing.T, data []byte) {
		readStringProperty(data)
	})
}

func FuzzVLCUnmarshal(f *testing.F) {
	// Seed: valid BACnet Virtual Link Control headers
	// Type 0x81 (BACnet/IP), Function, Length
	f.Add([]byte{0x81, 0x0A, 0x00, 0x10})                   // Original-Unicast-NPDU
	f.Add([]byte{0x81, 0x0B, 0x00, 0x10})                   // Original-Broadcast-NPDU
	f.Add([]byte{0x81, 0x04, 0x00, 0x10})                   // Forwarded-NPDU
	f.Add([]byte{0x81, 0x00, 0x00, 0x04})                   // BVLC-Result
	f.Add([]byte{0x81, 0x09, 0x00, 0x12, 0xC0, 0xA8, 0x01, 0x64, 0xBA, 0xC0}) // Register-Foreign-Device

	f.Fuzz(func(t *testing.T, data []byte) {
		var v VLC
		v.Unmarshal(data)
	})
}

func FuzzNPDUUnmarshal(f *testing.F) {
	// Seed: valid BACnet Network Protocol Data Units
	f.Add([]byte{0x01, 0x00})                               // Version 1, no flags
	f.Add([]byte{0x01, 0x08})                               // Version 1, destination specifier present
	f.Add([]byte{0x01, 0x04})                               // Version 1, source specifier present
	f.Add([]byte{0x01, 0x20})                               // Version 1, expecting reply
	f.Add([]byte{0x01, 0x0C, 0x00, 0x01, 0x01, 0x00, 0x02}) // Version 1, dst + src present

	f.Fuzz(func(t *testing.T, data []byte) {
		var n NPDU
		n.Unmarshal(data)
	})
}

func FuzzAPDUUnmarshal(f *testing.F) {
	// Seed: valid BACnet Application Protocol Data Units
	// Confirmed-REQ, Unconfirmed-REQ, SimpleACK, ComplexACK, Error, Reject, Abort
	f.Add([]byte{0x00, 0x00, 0x0F, 0x0C, 0x00, 0x00, 0x00, 0x01}) // Confirmed-REQ ReadProperty
	f.Add([]byte{0x10, 0x00})                                       // Unconfirmed-REQ WhoIs
	f.Add([]byte{0x20, 0x00, 0x0F})                                 // SimpleACK
	f.Add([]byte{0x30, 0x00, 0x0F})                                 // ComplexACK
	f.Add([]byte{0x50, 0x00, 0x0F, 0x00, 0x00})                     // Error PDU
	f.Add([]byte{0x60, 0x00, 0x01})                                 // Reject PDU
	f.Add([]byte{0x70, 0x00, 0x00})                                 // Abort PDU

	f.Fuzz(func(t *testing.T, data []byte) {
		var a APDU
		a.Unmarshal(data)
	})
}
