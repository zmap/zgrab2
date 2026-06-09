package omronfins

import (
	"encoding/hex"
	"net"
	"testing"
)

// FuzzGetDeviceInfo fuzzes the GetDeviceInfo parsing function directly.
func FuzzGetDeviceInfo(f *testing.F) {
	// Seed: valid UDP response payload starting at offset 12 (response code + device fields)
	// This is the tail of the CP1L UDP response from the unit tests.
	f.Add(
		hexMustDecode("00004350314c2d454d343044522d440000002020202030312e3030000000000030312e3037000000000008000000000000000000000000000000000000010000000000000000000000000000000000010004001417800008000000000000"),
		0,
	)
	// Seed: non-zero response code (service interrupted)
	f.Add([]byte{0x00, 0x01}, 0)
	// Seed: zero response code but truncated (no device fields)
	f.Add([]byte{0x00, 0x00}, 0)
	// Seed: minimal 2-byte with non-zero offset
	f.Add([]byte{0x00, 0x00, 0x00, 0x00}, 2)

	f.Fuzz(func(t *testing.T, data []byte, offset int) {
		if offset < 0 || offset >= len(data) {
			return
		}
		if offset+2 > len(data) {
			return
		}
		result := &DeviceInfo{}
		GetDeviceInfo(data, len(data), offset, result)
	})
}

// FuzzQueryDeviceUDP fuzzes the UDP query path with arbitrary server responses.
func FuzzQueryDeviceUDP(f *testing.F) {
	// Seed: valid CP1L UDP response
	f.Add(hexMustDecode("c00002006300000300ef050100004350314c2d454d343044522d440000002020202030312e3030000000000030312e3037000000000008000000000000000000000000000000000000010000000000000000000000000000000000010004001417800008000000000000"))
	// Seed: too short
	f.Add([]byte{0xc0, 0x00})
	// Seed: wrong magic byte
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// Seed: valid header prefix but truncated payload
	f.Add([]byte{0xc0, 0x00, 0x02, 0x00, 0x63, 0x00, 0x00, 0x03, 0x00, 0xef, 0x05, 0x01, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		clientConn, serverConn := net.Pipe()
		done := make(chan struct{})

		go func() {
			defer close(done)
			defer serverConn.Close()
			buf := make([]byte, 1024)
			serverConn.Read(buf)
			serverConn.Write(data)
		}()

		_, _ = QueryDeviceUDP(clientConn)
		clientConn.Close()
		<-done
	})
}

// FuzzQueryDeviceTCP fuzzes the TCP query path with arbitrary server responses.
func FuzzQueryDeviceTCP(f *testing.F) {
	// Seed: valid CP1L TCP address response + query response pair
	f.Add(
		hexMustDecode("46494e53000000100000000100000000000000fb00000021"),
		hexMustDecode("46494e53000000720000000200000000c0000200fbef00210005050100004350314c2d454d343044522d440000002020202030312e3030000000000030312e3038000000000000000000000000000000000000000000000000010000000000000000000000000000000000010100001417800008000000000000"),
	)
	// Seed: valid FINS header but short
	f.Add(
		hexMustDecode("46494e530000000800000001000000000000000000000000"),
		[]byte{0x00},
	)
	// Seed: non-FINS response
	f.Add(
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]byte{0x00},
	)
	// Seed: empty responses
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, response1 []byte, response2 []byte) {
		clientConn, serverConn := net.Pipe()
		done := make(chan struct{})

		go func() {
			defer close(done)
			defer serverConn.Close()
			buf := make([]byte, 1024)
			// Read the address request
			serverConn.Read(buf)
			// Send first response (address assignment)
			serverConn.Write(response1)
			// Read the query request
			serverConn.Read(buf)
			// Send second response (device info)
			serverConn.Write(response2)
		}()

		_, _ = QueryDeviceTCP(clientConn)
		clientConn.Close()
		<-done
	})
}

func hexMustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex in test seed: " + err.Error())
	}
	return b
}
