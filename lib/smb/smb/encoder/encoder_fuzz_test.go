package encoder

import (
	"encoding/binary"
	"testing"
)

// FuzzTestStruct exercises various encoder capabilities
type FuzzTestStruct struct {
	U8Field      uint8
	U16Field     uint16
	U32Field     uint32
	U64Field     uint64
	FixedBytes   []byte `smb:"fixed:8"`
	LenField     uint16 `smb:"len:VarBytes"`
	OffsetField  uint16 `smb:"offset:VarBytes"`
	VarBytes     []byte
	NestedStruct struct {
		A uint16
		B uint32
	}
}

// SimpleFuzzStruct provides basic type coverage
type SimpleFuzzStruct struct {
	Magic  []byte `smb:"fixed:4"`
	Count  uint16
	Status uint32
	Flags  uint64
}

// FuzzUnmarshal exercises the encoder's Unmarshal function with various binary inputs
func FuzzUnmarshal(f *testing.F) {
	// Seed 1: Valid SimpleFuzzStruct
	seed1 := make([]byte, 18) // 4 + 2 + 4 + 8 bytes
	copy(seed1[0:4], []byte("\xFE\x53\x4D\x42")) // Magic: ╙■SMB
	binary.LittleEndian.PutUint16(seed1[4:6], 42)
	binary.LittleEndian.PutUint32(seed1[6:10], 0x00000000)
	binary.LittleEndian.PutUint64(seed1[10:18], 0x1122334455667788)
	f.Add(seed1)

	// Seed 2: All zeros
	seed2 := make([]byte, 18)
	f.Add(seed2)

	// Seed 3: All ones
	seed3 := make([]byte, 18)
	for i := range seed3 {
		seed3[i] = 0xFF
	}
	f.Add(seed3)

	// Seed 4: Minimal input
	seed4 := make([]byte, 1)
	f.Add(seed4)

	// Seed 5: Valid FuzzTestStruct with fixed and variable fields
	seed5 := make([]byte, 64)
	seed5[0] = 0x01                                      // U8Field
	binary.LittleEndian.PutUint16(seed5[1:3], 0x0200)   // U16Field
	binary.LittleEndian.PutUint32(seed5[3:7], 0x03000000) // U32Field
	binary.LittleEndian.PutUint64(seed5[7:15], 0x0400000000000000) // U64Field
	copy(seed5[15:23], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}) // FixedBytes
	binary.LittleEndian.PutUint16(seed5[23:25], 4)      // LenField (length of VarBytes)
	binary.LittleEndian.PutUint16(seed5[25:27], 33)     // OffsetField (offset to VarBytes)
	// VarBytes at offset 33 (4 bytes)
	copy(seed5[33:37], []byte{0xDE, 0xAD, 0xBE, 0xEF})
	// NestedStruct after offset/len fields
	binary.LittleEndian.PutUint16(seed5[27:29], 0x1234) // NestedStruct.A
	binary.LittleEndian.PutUint32(seed5[29:33], 0x56789ABC) // NestedStruct.B
	f.Add(seed5)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Test SimpleFuzzStruct
		var simple SimpleFuzzStruct
		_ = Unmarshal(data, &simple)

		// Test FuzzTestStruct
		var complex FuzzTestStruct
		_ = Unmarshal(data, &complex)

		// Test pointer variant
		var simplePtr *SimpleFuzzStruct = &SimpleFuzzStruct{}
		_ = Unmarshal(data, simplePtr)
	})
}

// SMBHeaderV2 mimics the SMB2/3 Header structure
type SMBHeaderV2 struct {
	ProtocolID    []byte `smb:"fixed:4"`
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credits       uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     []byte `smb:"fixed:16"`
}

// SMBHeaderV1 mimics the SMB1 Header structure
type SMBHeaderV1 struct {
	ProtocolID       []byte `smb:"fixed:4"`
	Command          uint8
	Status           uint32
	Flags            uint8
	Flags2           uint16
	PIDHigh          uint16
	SecurityFeatures []byte `smb:"fixed:8"`
	Reserved         uint16
	TID              uint16
	PIDLow           uint16
	UID              uint16
	MID              uint16
}

// FuzzUnmarshalSMBHeader exercises realistic SMB header unmarshaling
func FuzzUnmarshalSMBHeader(f *testing.F) {
	// Seed 1: Valid SMB2 header
	v2seed := make([]byte, 64)
	copy(v2seed[0:4], []byte("\xFE\x53\x4D\x42")) // ╙■SMB
	binary.LittleEndian.PutUint16(v2seed[4:6], 64)    // StructureSize
	binary.LittleEndian.PutUint16(v2seed[6:8], 1)     // CreditCharge
	binary.LittleEndian.PutUint32(v2seed[8:12], 0)    // Status (OK)
	binary.LittleEndian.PutUint16(v2seed[12:14], 0)   // Command (Negotiate)
	binary.LittleEndian.PutUint16(v2seed[14:16], 1)   // Credits
	binary.LittleEndian.PutUint32(v2seed[16:20], 0)   // Flags
	binary.LittleEndian.PutUint32(v2seed[20:24], 0)   // NextCommand
	binary.LittleEndian.PutUint64(v2seed[24:32], 1)   // MessageID
	binary.LittleEndian.PutUint32(v2seed[32:36], 0)   // Reserved
	binary.LittleEndian.PutUint32(v2seed[36:40], 0)   // TreeID
	binary.LittleEndian.PutUint64(v2seed[40:48], 0)   // SessionID
	// Signature (16 bytes) at offset 48-64
	f.Add(v2seed)

	// Seed 2: Valid SMB1 header
	v1seed := make([]byte, 32)
	copy(v1seed[0:4], []byte("\xFF\x53\x4D\x42")) // ˙■SMB
	v1seed[4] = 0x72                                 // Command (Negotiate)
	binary.LittleEndian.PutUint32(v1seed[5:9], 0)  // Status
	v1seed[9] = 0x18                                 // Flags
	binary.LittleEndian.PutUint16(v1seed[10:12], 0xc843) // Flags2
	binary.LittleEndian.PutUint16(v1seed[12:14], 0)      // PIDHigh
	// SecurityFeatures (8 bytes) at offset 14-22
	binary.LittleEndian.PutUint16(v1seed[22:24], 0)      // Reserved
	binary.LittleEndian.PutUint16(v1seed[24:26], 0xFFFF) // TID
	binary.LittleEndian.PutUint16(v1seed[26:28], 0xFEFF) // PIDLow
	binary.LittleEndian.PutUint16(v1seed[28:30], 0)      // UID
	binary.LittleEndian.PutUint16(v1seed[30:32], 0)      // MID
	f.Add(v1seed)

	// Seed 3: Truncated header
	truncated := make([]byte, 10)
	copy(truncated[0:4], []byte("\xFE\x53\x4D\x42"))
	f.Add(truncated)

	// Seed 4: Wrong protocol ID
	wrongProto := make([]byte, 64)
	copy(wrongProto[0:4], []byte("FAKE"))
	f.Add(wrongProto)

	// Seed 5: Empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try unmarshaling as SMB2 header
		var v2hdr SMBHeaderV2
		_ = Unmarshal(data, &v2hdr)

		// Try unmarshaling as SMB1 header
		var v1hdr SMBHeaderV1
		_ = Unmarshal(data, &v1hdr)

		// Test pointer variants
		var v2ptr *SMBHeaderV2 = &SMBHeaderV2{}
		_ = Unmarshal(data, v2ptr)

		var v1ptr *SMBHeaderV1 = &SMBHeaderV1{}
		_ = Unmarshal(data, v1ptr)
	})
}

// VariableLengthStruct tests len/offset tag handling
type VariableLengthStruct struct {
	FixedHeader []byte `smb:"fixed:4"`
	DataLen     uint16 `smb:"len:Data"`
	DataOffset  uint16 `smb:"offset:Data"`
	Padding     uint32
	Data        []byte
}

// FuzzUnmarshalVariableLength exercises variable-length field handling
func FuzzUnmarshalVariableLength(f *testing.F) {
	// Seed 1: Valid variable length structure
	seed1 := make([]byte, 32)
	copy(seed1[0:4], []byte("HEAD"))
	binary.LittleEndian.PutUint16(seed1[4:6], 8)   // DataLen
	binary.LittleEndian.PutUint16(seed1[6:8], 12)  // DataOffset
	binary.LittleEndian.PutUint32(seed1[8:12], 0)  // Padding
	copy(seed1[12:20], []byte("TESTDATA"))
	f.Add(seed1)

	// Seed 2: Zero length data
	seed2 := make([]byte, 12)
	copy(seed2[0:4], []byte("HEAD"))
	binary.LittleEndian.PutUint16(seed2[4:6], 0)  // DataLen = 0
	binary.LittleEndian.PutUint16(seed2[6:8], 12) // DataOffset
	binary.LittleEndian.PutUint32(seed2[8:12], 0) // Padding
	f.Add(seed2)

	// Seed 3: Invalid offset (beyond buffer)
	seed3 := make([]byte, 12)
	copy(seed3[0:4], []byte("HEAD"))
	binary.LittleEndian.PutUint16(seed3[4:6], 100)   // DataLen = 100
	binary.LittleEndian.PutUint16(seed3[6:8], 1000)  // DataOffset = 1000 (invalid)
	binary.LittleEndian.PutUint32(seed3[8:12], 0)
	f.Add(seed3)

	// Seed 4: Overlapping offset
	seed4 := make([]byte, 20)
	copy(seed4[0:4], []byte("HEAD"))
	binary.LittleEndian.PutUint16(seed4[4:6], 4)  // DataLen = 4
	binary.LittleEndian.PutUint16(seed4[6:8], 2)  // DataOffset = 2 (overlaps header)
	binary.LittleEndian.PutUint32(seed4[8:12], 0)
	f.Add(seed4)

	f.Fuzz(func(t *testing.T, data []byte) {
		var vls VariableLengthStruct
		_ = Unmarshal(data, &vls)
	})
}

// NestedStruct tests nested structure unmarshaling
type OuterStruct struct {
	Magic  uint32
	Inner  InnerStruct
	Suffix uint16
}

type InnerStruct struct {
	A uint8
	B uint16
	C uint32
}

// FuzzUnmarshalNested exercises nested struct decoding
func FuzzUnmarshalNested(f *testing.F) {
	// Seed 1: Valid nested structure
	seed := make([]byte, 13) // 4 + 7 (1+2+4) + 2
	binary.LittleEndian.PutUint32(seed[0:4], 0xDEADBEEF)
	seed[4] = 0x11
	binary.LittleEndian.PutUint16(seed[5:7], 0x2222)
	binary.LittleEndian.PutUint32(seed[7:11], 0x33333333)
	binary.LittleEndian.PutUint16(seed[11:13], 0x4444)
	f.Add(seed)

	// Seed 2: Zeros
	f.Add(make([]byte, 13))

	// Seed 3: Truncated
	f.Add(make([]byte, 5))

	f.Fuzz(func(t *testing.T, data []byte) {
		var outer OuterStruct
		_ = Unmarshal(data, &outer)
	})
}
