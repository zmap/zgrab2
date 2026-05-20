package codesys2

import (
	"encoding/binary"
	"testing"
)

func FuzzUnMarshalHeader(f *testing.F) {
	f.Add([]byte{0xBB, 0xBB, 0x00, 0x00, 0x00, 0x00}, true)
	f.Add([]byte{0xBB, 0xBB, 0x00, 0x00, 0x00, 0x00}, false)
	f.Fuzz(func(t *testing.T, data []byte, useBigEndian bool) {
		var byteOrder binary.ByteOrder
		if useBigEndian {
			byteOrder = binary.BigEndian
		} else {
			byteOrder = binary.LittleEndian
		}
		header := &CodeSysV2Header{}
		_ = UnMarshal(data, byteOrder, header)
	})
}

func FuzzUnMarshalRequest(f *testing.F) {
	f.Add(make([]byte, 6), true)
	f.Add(make([]byte, 6), false)
	f.Fuzz(func(t *testing.T, data []byte, useBigEndian bool) {
		var byteOrder binary.ByteOrder
		if useBigEndian {
			byteOrder = binary.BigEndian
		} else {
			byteOrder = binary.LittleEndian
		}
		request := &CodeSysV2Request{}
		_ = UnMarshal(data, byteOrder, request)
	})
}
