package mqtt

import (
	"net"
	"testing"
)

func FuzzReadMQTTv3Packet(f *testing.F) {
	// Add seed corpus
	f.Add([]byte("\x20\x02\x00\x00"))                   // MQTT CONNACK packet
	f.Add([]byte("\x30\x05\x00\x01a\x68\x69"))          // MQTT PUBLISH packet
	f.Add([]byte("\xE0\x00"))                           // DISCONNECT packet
	f.Add([]byte("\x20\x02\x01\x00"))                   // CONNACK with session present
	f.Add([]byte("\x20\x02\x00\x05"))                   // CONNACK with return code 5

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a pipe to simulate network connection
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		// Create Connection with the client side of the pipe
		conn := &Connection{
			conn:   client,
			config: &Flags{},
		}

		// Write fuzz data in a goroutine
		go func() {
			server.Write(data)
			server.Close()
		}()

		// Call ReadMQTTv3Packet and let panics propagate
		_ = conn.ReadMQTTv3Packet()
	})
}

func FuzzReadMQTTv5Packet(f *testing.F) {
	// Add seed corpus
	f.Add([]byte("\x20\x02\x00\x00"))                   // MQTT CONNACK packet
	f.Add([]byte("\x30\x05\x00\x01a\x68\x69"))          // MQTT PUBLISH packet
	f.Add([]byte("\xE0\x00"))                           // DISCONNECT packet
	f.Add([]byte("\x20\x03\x00\x00\x00"))               // CONNACK v5 with properties length 0
	f.Add([]byte("\x20\x04\x01\x00\x00\x00"))           // CONNACK v5 with session present

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a pipe to simulate network connection
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		// Create Connection with the client side of the pipe
		conn := &Connection{
			conn:   client,
			config: &Flags{V5: true},
		}

		// Write fuzz data in a goroutine
		go func() {
			server.Write(data)
			server.Close()
		}()

		// Call ReadMQTTv5Packet and let panics propagate
		_ = conn.ReadMQTTv5Packet()
	})
}
