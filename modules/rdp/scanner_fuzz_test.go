package rdp

import (
	"net"
	"testing"
)

func FuzzReadAvItem(f *testing.F) {
	f.Add(make([]byte, 4))
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readAvItem(data, 0, 0, len(data))
	})
}

func FuzzX224Negotiate(f *testing.F) {
	f.Add([]byte{0x03, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add(make([]byte, 19))
	f.Fuzz(func(t *testing.T, data []byte) {
		reader, writer := net.Pipe()
		go func() {
			// x224Negotiate writes a request first, drain it
			buf := make([]byte, 1024)
			reader.Read(buf)
			// Then send fuzz data as the response
			reader.Write(data)
			reader.Close()
		}()
		_, _, _, _ = x224Negotiate(writer)
		writer.Close()
	})
}
