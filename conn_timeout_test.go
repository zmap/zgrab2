package zgrab2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// Config for a single timeout test
type connTimeoutTestConfig struct {
	// Name for the test for logging purposes
	name string

	// Optional explicit endpoint to connect to (if absent, use 127.0.0.1)
	endpoint string

	// TCP port number to communicate on
	port int

	// Function used to dial new connections
	dialer func() (*TimeoutConnection, error)

	// Client timeout values
	timeout             time.Duration
	connectTimeout      time.Duration
	readTimeout         time.Duration
	writeTimeout        time.Duration
	postConnReadTimeout time.Duration // set on conn after dialer gives it to us

	// Time for server to wait after listening before accepting a connection
	serverAcceptDelay time.Duration

	// Time for server to wait after accepting before writing payload
	serverWriteDelay time.Duration

	// Time for server to wait before reading payload
	serverReadDelay time.Duration

	// Payload for server to send client after connecting
	serverToClientPayload []byte

	// Payload for client to send server after reading the previous payload
	clientToServerPayload []byte

	// Step when the client is expected to fail
	clientFailStep testStep

	// If non-empty, the error string returned by the client should contain this
	failError string
}

// Standardized time units, separated by factors of 100.
const (
	short  = 10 * time.Millisecond
	medium = 1000 * time.Millisecond
	long   = 100000 * time.Millisecond
)

// enum type for the various locations where the test can fail
type testStep string

const (
	clientTestStepConnect = testStep("connect")
	clientTestStepRead    = testStep("read")
	clientTestStepWrite   = testStep("write")
	testStepDone          = testStep("done")
)

// Encapsulates a source for an error (client/server/???), the step where it occurred, and an
// optional cause.
type timeoutTestError struct {
	source string
	step   testStep
	cause  error
}

func (err *timeoutTestError) Error() string {
	return fmt.Sprintf("%s error at %s: %v", err.source, err.step, err.cause)
}

func serverError(step testStep, err error) *timeoutTestError {
	return &timeoutTestError{
		source: "server",
		step:   step,
		cause:  err,
	}
}

func clientError(step testStep, err error) *timeoutTestError {
	return &timeoutTestError{
		source: "client",
		step:   step,
		cause:  err,
	}
}

// Helper to ensure all data is written to a socket
func _write(writer io.Writer, data []byte) error {
	n, err := writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

// Run the configured server. As soon as it returns, it is listening.
// Returns a channel that receives a timeoutTestError on error, or is closed on successful completion.
func (cfg *connTimeoutTestConfig) runServer(t *testing.T, stopServer <-chan struct{}) chan *timeoutTestError {
	errorChan := make(chan *timeoutTestError)
	if cfg.endpoint != "" {
		// Only listen on localhost
		return errorChan
	}
	listener, err := net.Listen("tcp", cfg.getEndpoint())
	if err != nil {
		logrus.Fatalf("Error listening: %v", err)
	}
	go func() {
		defer listener.Close()
		defer close(errorChan)
		time.Sleep(cfg.serverAcceptDelay)
		sock, err := listener.Accept()
		if err != nil {
			errorChan <- serverError(clientTestStepConnect, err)
			return
		}
		defer sock.Close()
		time.Sleep(cfg.serverWriteDelay)
		if err = _write(sock, cfg.serverToClientPayload); err != nil {
			errorChan <- serverError(clientTestStepRead, err)
			return
		}
		time.Sleep(cfg.serverReadDelay)
		buf := make([]byte, len(cfg.clientToServerPayload))
		n, err := io.ReadFull(sock, buf)
		if err != nil && err != io.EOF {
			errorChan <- serverError(clientTestStepWrite, err)
			return
		}
		if err == io.EOF && n < len(buf) {
			errorChan <- serverError(clientTestStepWrite, err)
			return
		}
		if !bytes.Equal(buf, cfg.clientToServerPayload) {
			t.Errorf("%s: clientToServerPayload mismatch", cfg.name)
		}
		<-stopServer // wait for client to indicate server can exit
	}()
	return errorChan
}

// Get the configured endpoint
func (cfg *connTimeoutTestConfig) getEndpoint() string {
	if cfg.endpoint != "" {
		return cfg.endpoint
	}
	return fmt.Sprintf("127.0.0.1:%d", cfg.port)
}

// Dial a connection to the configured endpoint using a Dialer
func (cfg *connTimeoutTestConfig) dialerDial() (*TimeoutConnection, error) {
	dialer := NewDialer(&Dialer{
		SessionTimeout: cfg.timeout,
		ReadTimeout:    cfg.readTimeout,
		WriteTimeout:   cfg.writeTimeout,
	})
	dialer.Timeout = cfg.connectTimeout
	ret, err := dialer.Dial("tcp", cfg.getEndpoint())
	if err != nil {
		return nil, err
	}
	if cfg.postConnReadTimeout > 0 {
		err = ret.SetReadDeadline(time.Now().Add(cfg.postConnReadTimeout))
		if err != nil {
			return nil, err
		}
	}
	return ret.(*TimeoutConnection), err
}

// Dial a connection to the configured endpoint using a DialTimeoutConnectionEx
func (cfg *connTimeoutTestConfig) directDial() (*TimeoutConnection, error) {
	dialer := NewDialer(&Dialer{
		SessionTimeout: cfg.timeout,
		ReadTimeout:    cfg.readTimeout,
		WriteTimeout:   cfg.writeTimeout,
	})
	dialer.Timeout = cfg.connectTimeout

	ret, err := dialer.Dial("tcp", cfg.getEndpoint())
	if err != nil {
		return nil, err
	}
	if cfg.postConnReadTimeout > 0 {
		err = ret.SetReadDeadline(time.Now().Add(cfg.postConnReadTimeout))
		if err != nil {
			return nil, err
		}
	}
	return ret.(*TimeoutConnection), err
}

// Dial a connection to the configured endpoint using Dialer.DialContext
func (cfg *connTimeoutTestConfig) contextDial() (*TimeoutConnection, error) {
	dialer := NewDialer(&Dialer{
		SessionTimeout: cfg.timeout,
		ReadTimeout:    cfg.readTimeout,
		WriteTimeout:   cfg.writeTimeout,
	})
	dialer.Timeout = cfg.connectTimeout
	ret, err := dialer.DialContext(context.Background(), "tcp", cfg.getEndpoint())
	if err != nil {
		return nil, err
	}
	if cfg.postConnReadTimeout > 0 {
		err = ret.SetReadDeadline(time.Now().Add(cfg.postConnReadTimeout))
		if err != nil {
			return nil, err
		}
	}
	return ret.(*TimeoutConnection), err
}

// Run the client: connect to the server, read the payload, write the payload, disconnect.
func (cfg *connTimeoutTestConfig) runClient(t *testing.T) (testStep, error) {
	conn, err := cfg.dialer()
	if err != nil {
		return clientTestStepConnect, err
	}
	defer conn.Close()
	buf := make([]byte, len(cfg.serverToClientPayload))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return clientTestStepRead, err
	}
	if !bytes.Equal(cfg.serverToClientPayload, buf) {
		t.Errorf("%s: serverToClientPayload payload mismatch", cfg.name)
	}
	if err := _write(conn, cfg.clientToServerPayload); err != nil {
		return clientTestStepWrite, err
	}
	return testStepDone, nil
}

// Run the configured test -- start a server and a client to connect to it.
func (cfg *connTimeoutTestConfig) run(t *testing.T) {
	done := make(chan *timeoutTestError)
	stopServer := make(chan struct{})
	serverError := cfg.runServer(t, stopServer)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				close(done)
				panic(err)
			}
		}()
		step, err := cfg.runClient(t)
		done <- clientError(step, err)
	}()
	go func() {
		time.Sleep(long + medium + short)
		done <- &timeoutTestError{source: "timeout"}
	}()
	var ret *timeoutTestError
	select {
	case err := <-serverError:
		t.Fatalf("%s: Server error: %v", cfg.name, err)
	case ret = <-done:
		if ret == nil {
			t.Fatalf("Channel unexpectedly closed")
		}
	}
	close(stopServer)
	if ret.source != "client" {
		t.Fatalf("%s: Unexpected error from %s: %v", cfg.name, ret.source, ret.cause)
	}
	if ret.step != cfg.clientFailStep {
		t.Errorf("%s: Failed at step %s, but expected to fail at step %s (error=%v)", cfg.name, ret.step, cfg.clientFailStep, ret.cause)
		return
	}
	if cfg.failError != "" {
		errString := "none"
		if ret.cause != nil {
			errString = ret.cause.Error()
		}
		if !strings.Contains(errString, cfg.failError) {
			t.Errorf("%s: Expected an error (%s) at step %s, got %s", cfg.name, cfg.failError, cfg.clientFailStep, errString)
			return
		}
	} else if ret.cause != nil {
		t.Errorf("%s: expected no error at step %s, but got %v", cfg.name, cfg.clientFailStep, ret.cause)
	}
}

var connTestConfigs = []connTimeoutTestConfig{
	// Long timeouts, short delays -- should succeed
	{
		name:           "happy",
		port:           0x5613,
		timeout:        long,
		connectTimeout: medium,
		readTimeout:    medium,
		writeTimeout:   medium,

		serverAcceptDelay: short,
		serverWriteDelay:  short,
		serverReadDelay:   short,

		serverToClientPayload: []byte("abc"),
		clientToServerPayload: []byte("defghi"),

		clientFailStep: testStepDone,
	},
	//// long session timeout, short connectTimeout. Use a non-local, nonexistent endpoint (localhost
	//// would return "connection refused" immediately)
	{
		name:           "connect_timeout",
		endpoint:       "10.0.254.254:41591",
		timeout:        long,
		connectTimeout: short,
		readTimeout:    medium,
		writeTimeout:   medium,

		serverAcceptDelay: short,
		serverWriteDelay:  short,
		serverReadDelay:   short,

		serverToClientPayload: []byte("abc"),
		clientToServerPayload: []byte("defghi"),

		clientFailStep: clientTestStepConnect,
		failError:      "i/o timeout",
	},
	//// short session timeout, medium connect timeout, with connect to nonexistent endpoint.
	{
		name:           "session_connect_timeout",
		endpoint:       "10.0.254.254:41591",
		timeout:        short,
		connectTimeout: medium,
		readTimeout:    medium,
		writeTimeout:   medium,

		serverAcceptDelay: short,
		serverWriteDelay:  short,
		serverReadDelay:   short,

		serverToClientPayload: []byte("abc"),
		clientToServerPayload: []byte("defghi"),

		clientFailStep: clientTestStepConnect,
		failError:      "i/o timeout",
	},
	//// Get an IO timeout on the read.
	//// sessionTimeout > serverAcceptDelay + serverWriteDelay > serverWriteDelay > readTimeout
	{
		name:           "read_timeout",
		port:           0x5614,
		timeout:        long,
		connectTimeout: short,
		readTimeout:    short,
		writeTimeout:   short,

		serverAcceptDelay: short,
		serverWriteDelay:  medium,
		serverReadDelay:   short,

		serverToClientPayload: []byte("abc"),
		clientToServerPayload: []byte("defghi"),

		clientFailStep: clientTestStepRead,
		failError:      "i/o timeout",
	},
	// Get a context timeout on a read.
	// readTimeout > serverWriteDelay > timeout > serverAcceptDelay
	{
		name:           "session_read_timeout",
		port:           0x5615,
		timeout:        short,
		connectTimeout: long,
		readTimeout:    long,
		writeTimeout:   long,

		serverAcceptDelay: 0,
		serverWriteDelay:  medium * 2,
		serverReadDelay:   0,

		serverToClientPayload: []byte("abc"),
		clientToServerPayload: []byte("defghi"),

		clientFailStep: clientTestStepRead,
		failError:      "i/o timeout",
	},
	// Use a session timeout that is longer than any individual action's timeout.
	// serverAcceptDelay+serverWriteDelay+serverReadDelay > timeout > serverAcceptDelay >= serverWriteDelay >= serverReadDelay
	{
		name:           "session_timeout",
		port:           0x5616,
		timeout:        medium,
		connectTimeout: long,
		readTimeout:    long,
		writeTimeout:   long,

		serverAcceptDelay: time.Nanosecond * time.Duration(medium.Nanoseconds()/2+short.Nanoseconds()),
		serverWriteDelay:  time.Nanosecond * time.Duration(medium.Nanoseconds()/2+short.Nanoseconds()),
		serverReadDelay:   time.Nanosecond * time.Duration(medium.Nanoseconds()/2+short.Nanoseconds()),

		serverToClientPayload: []byte("abc"),
		clientToServerPayload: []byte("defghi"),

		clientFailStep: clientTestStepRead,
		failError:      "i/o timeout",
	},
	// Use a session timeout that is longer than any individual action's timeout.
	// serverAcceptDelay+serverWriteDelay+serverReadDelay > timeout > serverAcceptDelay >= serverWriteDelay >= serverReadDelay
	{
		name:                "post conn read timeout",
		port:                0x5617,
		timeout:             long,
		connectTimeout:      long,
		readTimeout:         short, // if the post Conn timeout isn't set appropriately, this will be the read timeout, causing the test to fail
		writeTimeout:        long,
		postConnReadTimeout: medium * 2, // we'll apply this after dialing, connection should succeed

		serverWriteDelay: medium,

		serverToClientPayload: []byte("abc"),
		clientToServerPayload: []byte("defghi"),

		clientFailStep: testStepDone,
	},
	// TODO: How to test write timeout?
}

// TestTimeoutConnectionTimeouts tests that the TimeoutConnection behaves as expected with respect
// to timeouts.
func TestTimeoutConnectionTimeouts(t *testing.T) {
	temp := make([]connTimeoutTestConfig, 0, len(connTestConfigs)*3)
	// Make three copies of connTestConfigs, one with each dial method.
	for _, cfg := range connTestConfigs {
		direct := cfg
		dialer := cfg
		ctxDialer := cfg

		dialer.name = dialer.name + "_dialer"
		dialer.port = dialer.port + 100
		dialer.dialer = dialer.dialerDial

		direct.name = direct.name + "_direct"
		direct.port = direct.port + 200
		direct.dialer = direct.directDial

		ctxDialer.name = ctxDialer.name + "_context"
		ctxDialer.port = ctxDialer.port + 300
		ctxDialer.dialer = ctxDialer.contextDial
		temp = append(temp, direct, dialer, ctxDialer)
	}
	for _, cfg := range temp {
		t.Logf("Running %s", cfg.name)
		cfg.run(t)
	}
}
