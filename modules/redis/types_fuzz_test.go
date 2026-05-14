package redis

import (
	"net"
	"testing"
)

func FuzzReadRedisValue(f *testing.F) {
	// Add seed corpus entries for valid Redis protocol messages
	f.Add([]byte("+OK\r\n"))                    // Simple string
	f.Add([]byte("-ERR unknown\r\n"))           // Error
	f.Add([]byte(":42\r\n"))                    // Integer
	f.Add([]byte("$5\r\nhello\r\n"))            // Bulk string
	f.Add([]byte("$-1\r\n"))                    // Null
	f.Add([]byte("*2\r\n+hello\r\n+world\r\n")) // Array
	f.Add([]byte("*0\r\n"))                     // Empty array
	f.Add([]byte("*1\r\n*1\r\n+ok\r\n"))        // Nested array

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a pipe for testing
		reader, writer := net.Pipe()

		// Write fuzz data in a goroutine
		go func() {
			writer.Write(data)
			writer.Close()
		}()

		// Create a Connection with the reader end
		conn := &Connection{
			conn: reader,
		}

		// Call ReadRedisValue - let any panic propagate naturally
		_, _ = conn.ReadRedisValue()

		// Close the reader
		reader.Close()
	})
}
