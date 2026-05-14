package siemens

import "testing"

// FuzzTPKTPacketUnmarshal fuzzes the TPKTPacket.Unmarshal method
func FuzzTPKTPacketUnmarshal(f *testing.F) {
	// Seed corpus: TPKT packets need at least 4 bytes
	// Format: version(1) + reserved(1) + length(2)
	f.Add([]byte("\x03\x00\x00\x04"))                     // Minimal valid TPKT
	f.Add([]byte("\x03\x00\x00\x10extra data here"))      // TPKT with payload
	f.Add([]byte("\x03\x00\x00\x08\x00\x00\x00\x00"))     // 8-byte TPKT
	f.Add([]byte("\x03\x00\x01\x00" + string(make([]byte, 252)))) // Larger packet

	f.Fuzz(func(t *testing.T, data []byte) {
		var pkt TPKTPacket
		pkt.Unmarshal(data)
	})
}

// FuzzCOTPConnectionPacketUnmarshal fuzzes the COTPConnectionPacket.Unmarshal method
func FuzzCOTPConnectionPacketUnmarshal(f *testing.F) {
	// Seed corpus: COTP Connection packets need at least 7 bytes
	// Format: length(1) + PDU_type(1) + dst_ref(2) + src_ref(2) + class(1) + ...
	f.Add([]byte("\x06\xe0\x00\x00\x00\x01\x00"))                           // Minimal COTP CR
	f.Add([]byte("\x11\xd0\x00\x01\x00\x02\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02")) // COTP CC with parameters
	f.Add([]byte("\x07\xe0\x00\x00\x00\x00\x00\x00"))                       // CR with extra byte
	f.Add([]byte("\x0a\xe0\xff\xff\x00\x01\x00\xc1\x02\x01\x00"))          // CR with parameter

	f.Fuzz(func(t *testing.T, data []byte) {
		var pkt COTPConnectionPacket
		pkt.Unmarshal(data)
	})
}

// FuzzCOTPDataPacketUnmarshal fuzzes the COTPDataPacket.Unmarshal method
func FuzzCOTPDataPacketUnmarshal(f *testing.F) {
	// Seed corpus: COTP Data packets need at least 3 bytes
	// Format: length(1) + PDU_type(1) + TPDU_number(1) + ...
	f.Add([]byte("\x02\xf0\x80"))                        // Minimal COTP DT
	f.Add([]byte("\x02\xf0\x00"))                        // DT with TPDU number 0
	f.Add([]byte("\x03\xf0\x80\x00"))                    // DT with one byte payload
	f.Add([]byte("\x0f\xf0\x80data payload here"))       // DT with longer payload

	f.Fuzz(func(t *testing.T, data []byte) {
		var pkt COTPDataPacket
		pkt.Unmarshal(data)
	})
}

// FuzzS7PacketUnmarshal fuzzes the S7Packet.Unmarshal method
func FuzzS7PacketUnmarshal(f *testing.F) {
	// Seed corpus: S7 packets need at least 10-12 bytes
	// Format: protocol_id(1) + msg_type(1) + reserved(2) + pdu_ref(2) + param_len(2) + data_len(2) + ...
	f.Add([]byte("\x32\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))                       // Minimal S7 header
	f.Add([]byte("\x32\x03\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00test"))                   // S7 with data
	f.Add([]byte("\x32\x07\x00\x00\x00\x02\x00\x08\x00\x00\x00\x00param---"))              // S7 with parameters
	f.Add([]byte("\x32\x01\x00\x00\x05\x39\x00\x08\x00\x08param---data----"))              // S7 with both
	f.Add([]byte("\x32\x02\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00"))                       // S7 with max PDU ref

	f.Fuzz(func(t *testing.T, data []byte) {
		var pkt S7Packet
		pkt.Unmarshal(data)
	})
}
