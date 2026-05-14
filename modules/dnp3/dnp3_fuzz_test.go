package dnp3

import (
	"net"
	"testing"
)

func FuzzGetDNP3Banner(f *testing.F) {
	// Seed: DNP3 response header - start bytes 0x05 0x64, length, control, dest(2), source(2), CRC(2), payload
	f.Add([]byte{0x05, 0x64, 0x0A, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		clientConn, serverConn := net.Pipe()
		done := make(chan struct{})
		
		go func() {
			defer close(done)
			defer serverConn.Close()
			// Read and discard the request that GetDNP3Banner writes
			buf := make([]byte, 1024)
			serverConn.Read(buf)
			// Then send fuzz data as response
			serverConn.Write(data)
		}()

		logStruct := &DNP3Log{}
		_ = GetDNP3Banner(logStruct, clientConn)
		clientConn.Close()
		<-done
	})
}
