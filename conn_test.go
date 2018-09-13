package zgrab2

import (
	"testing"
	"time"
	"fmt"
	"net"
	"io"
	"context"
	"sync"
)

var nextPort = 0x8765

type client struct {
	t *testing.T
	ctx context.Context
	dialer *Dialer
	conn net.Conn
	writeData []byte
	server *server
	readData []byte
}

const maxReadSize = 64 * 1024

var defaultClientPayload = []byte("GET / HTTP/1.0\r\n\r\n")
var defaultServerPayload = []byte("HTTP 200 OK\r\nContent-Length: 16\r\nContent-Type: application/x-pork-soda\r\n\r\n0123456789abcdef\r\n\r\n")

func (client *client) logf(format string, args...interface{}) {
	client.t.Logf(format, args...)
}

func dial(ctx context.Context, t *testing.T, server *server, dialer *Dialer) (*client, error) {
	conn, err :=  dialer.DialContext(ctx, "tcp", server.endpoint())
	if err != nil {
		t.Logf("Error dialing: %v", err)
		return nil, err
	}
	go func() {
		<-ctx.Done()
		if err := conn.Close(); err != nil {
			t.Logf("Error automatically closing client connection: %v", err)
		}
	}()
	return &client{
		t: t,
		writeData: defaultClientPayload,
		ctx: ctx,
		dialer: dialer,
		conn: conn,
		server: server,
	}, nil
}

func (client *client) run() error {
	n, err := client.conn.Write(client.writeData)
	if n != len(client.writeData) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		client.logf("Error writing client payload: %v", err)
		return err
	}
	buf := make([]byte, maxReadSize)
	n, err = client.conn.Read(buf);
	if err != nil {
		client.logf("Error reading server response: %v", err)
		return err
	}
	client.readData = buf[0:n]
	return nil
}

type server struct {
	t *testing.T
	port int
	listenTime time.Duration
	connectTime time.Duration
	readTime time.Duration
	writeTime time.Duration
	listener net.Listener
	serverSocket net.Conn
	clientSocket net.Conn
	readData []byte
	writeData []byte
}

func (server *server) logf(format string, args...interface{}) {
	msg := fmt.Sprintf(format, args...)
	server.t.Logf("[server 0x%04x]: %s", server.port, msg)
}

func (server *server) run() error {
	var err error
	time.Sleep(server.listenTime)
	if err := server.listen(); err != nil {
		server.logf("Error listening: %v", err)
		return err
	}
	time.Sleep(server.connectTime)
	server.serverSocket, err = server.listener.Accept()
	if err != nil {
		server.logf("Error accepting: %v", err)
		return err
	}
	defer func() {
		if err := server.serverSocket.Close(); err != nil {
			server.logf("Error closing: %v", err)
		}
	}()
	time.Sleep(server.readTime)
	buf := make([]byte, maxReadSize)
	n, err := server.serverSocket.Read(buf)
	if n > 0 {
		server.logf("Server read %d bytes", n)
		server.readData = buf[0:n]
	}
	if err != nil {
		server.logf("Error reading: %v", err)
		return err
	}
	time.Sleep(server.writeTime)
	if server.writeData != nil {
		n, err = server.serverSocket.Write(server.writeData)
		if n != len(server.writeData) {
			server.logf("Only wrote %d/%d bytes", n, len(server.writeData))
			return io.ErrShortWrite
		}
		server.logf("Wrote %d bytes", n)
	}

	return nil

}

func (server *server) endpoint() string {
	return fmt.Sprintf("localhost:%d", server.port)
}

func (server *server) Close() error {
	if server.serverSocket != nil {
		if err := server.serverSocket.Close(); err != nil {
			server.logf("Error closing server socket: %v", err)
		}
		server.serverSocket = nil
	}
	if err := server.listener.Close(); err != nil {
		server.logf("Error closing server listener: %v", err)
	}
	server.listener = nil
	return nil
}

func (server *server) listen() error {
	server.logf("Listening on port %d", server.port)
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", server.port));
	if err != nil {
		server.t.Fatalf("listen error: %v", err)
		return err
	}
	server.listener = listener
	return nil
}

var portMutex sync.Mutex

func getNextPort() int {
	portMutex.Lock()
	defer portMutex.Unlock()
	for p := nextPort; p <= 0xffff; p++ {
		l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", p))
		if l != nil {
			l.Close()
		}
		if err == nil {
			nextPort = p + 1
			return p
		}
	}
	panic("Out of ports")
}

func newServer(t *testing.T, listenTime, connectTime, readTime, writeTime time.Duration) (*server, error) {
	return &server{
		t: t,
		port: getNextPort(),
		listenTime: listenTime,
		connectTime: connectTime,
		readTime: readTime,
		writeTime: writeTime,
		writeData: defaultServerPayload,
	}, nil
}

func _startServer(t *testing.T, listenTime, connectTime, readTime, writeTime time.Duration) (*server, error) {
	ret, err := newServer(t, listenTime, connectTime, readTime, writeTime)
	if err != nil {
		return nil, err
	}
	return ret, ret.listen()
}

const S = time.Second
const MS = time.Millisecond

func TestDialerDialContext_Happy(t *testing.T) {
	dialer := &Dialer{
		ConnectTimeout: 1 * S,
		WriteTimeout: 2 * S,
		ReadTimeout: 3 * S,
		Timeout: 4 * S,
		Dialer: &net.Dialer{
			Timeout: 10 * S,
		},
	}
	server, err := newServer(t, 0, 500 * MS, 500 * MS, 500 * MS)
	if err != nil {
		t.Fatalf("Error starting server: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5 * S)
	var waiter sync.WaitGroup
	defer cancel();
	waiter.Add(2)
	go func() {
		defer waiter.Done()
		if err := server.run(); err != nil {
			t.Fatalf("Error running server: %v", err)
		}
	}()
	go func() {
		defer waiter.Done()
		client, err := dial(ctx, t, server, dialer)
		if err != nil {
			t.Fatalf("Error dialing client: %v", err)
		}
		if err := client.run(); err != nil {
			t.Fatalf("Error running client: %v", err)
		}
	}()
	waiter.Wait()
}

