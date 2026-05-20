package mongodb

import (
	"net"
	"testing"
)

func FuzzReadMsg(f *testing.F) {
	// Seed with a minimal valid MongoDB wire protocol message
	// Message format: messageLength(4) + requestID(4) + responseTo(4) + opCode(4) [+ payload]
	// 16-byte message: length=16, requestID=1, responseTo=0, opCode=OP_REPLY(1)
	seed := []byte{
		0x10, 0x00, 0x00, 0x00, // messageLength = 16 (little-endian)
		0x01, 0x00, 0x00, 0x00, // requestID = 1
		0x00, 0x00, 0x00, 0x00, // responseTo = 0
		0x01, 0x00, 0x00, 0x00, // opCode = OP_REPLY (1)
	}
	f.Add(seed)

	// Seed with OP_MSG
	seed2 := []byte{
		0x10, 0x00, 0x00, 0x00, // messageLength = 16
		0x02, 0x00, 0x00, 0x00, // requestID = 2
		0x00, 0x00, 0x00, 0x00, // responseTo = 0
		0xdd, 0x07, 0x00, 0x00, // opCode = OP_MSG (2013)
	}
	f.Add(seed2)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a pipe to simulate network connection
		reader, writer := net.Pipe()
		defer reader.Close()

		// Write fuzz data in a goroutine
		go func() {
			writer.Write(data)
			writer.Close()
		}()

		// Create Connection with the reader end
		conn := &Connection{
			conn: reader,
		}

		// Call ReadMsg - let panics propagate
		conn.ReadMsg()
	})
}
