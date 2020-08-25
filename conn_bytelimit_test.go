package zgrab2

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Start a local echo server on port.
func runEchoServer(t *testing.T, port int) {
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listener.Close()
		sock, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer sock.Close()

		buf := make([]byte, 1024)
		for {
			n, err := sock.Read(buf)
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "connection reset") {
					t.Fatal(err)
				}
				return
			}
			sock.SetWriteDeadline(time.Now().Add(time.Millisecond * 250))
			n, err = sock.Write(buf[0:n])
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "connection reset") && !strings.Contains(err.Error(), "broken pipe") {
					t.Logf("Unexpected error writing to client: %v", err)
				}
				return
			}
		}
	}()
}

// Interface for getting a TimeoutConnection; we want to test both the dialer and the direct Dial functions.
type timeoutConnector interface {
	connect(ctx context.Context, t *testing.T, port int, idx int) (*TimeoutConnection, error)
	getConfig() readLimitTestConfig
}

// Config for a test case
type readLimitTestConfig struct {
	// The maximum bytes the connection should read
	limit int
	// The number of bytes that should be sent (so iff sendSize > limit, the action should be triggered)
	sendSize int
	// The action to run when too much data is sent
	action ReadLimitExceededAction
}

// Call sendReceive(), and check that the input/output match, and that any expected errors / truncation occurs.
func checkedSendReceive(t *testing.T, conn *TimeoutConnection, size int) (result error) {
	// helper to report + return an error
	tErrorf := func(format string, args ...interface{}) error {
		result = fmt.Errorf(format, args)
		t.Error(result)
		return result
	}

	// We will check that this increases by the correct size
	before := conn.BytesRead

	// This is true if we expect an overflow to occur (and so the ReadLimitExceededAction should fire)
	overflowed := (before + size) > conn.BytesReadLimit

	// Don't want to keep re-typing this
	action := conn.ReadLimitExceededAction

	defer func() {
		if result != nil {
			// log any previous error -- more may still follow
			t.Error(result)
		}
		err := recover()
		if err != nil {
			if action != ReadLimitExceededActionPanic {
				// no reason to panic unless that is the action
				panic(err)
			}
			if !overflowed {
				tErrorf("panicked early: only sent %d bytes so far, but limit=%d", before+size, conn.BytesReadLimit)
				return
			}
			if err == ErrReadLimitExceeded {
				// We read too much data and this is the right error: silently succeed
				return
			}
			tErrorf("wrong panic error: got %v, expected ErrReadlimitExceeded", err)
			return
		}

		if action != ReadLimitExceededActionPanic {
			// other action -- fine that we didn't panic
			return
		}
		if !overflowed {
			// not enough bytes read to overflow -- fine that we didn't panic
			return
		}
		// ReadLimitExceededActionPanic, read too many bytes: should have panicked but didn't
		tErrorf("should have panicked: action=ReadLimitExceededActionPanic, but sent without issue")
	}()

	ret, err := sendReceive(t, conn, size)

	if err != nil {
		if !overflowed {
			// If there is no overflow, there should be no error
			return tErrorf("read: unexpected error: %v", err)
		}
		if err != io.EOF && err != ErrReadLimitExceeded {
			// EOF and ErrReadLimitExceeded are the only errors that should be returned
			return tErrorf("read: wrong error: %v", err)
		}
		if err == io.EOF && action != ReadLimitExceededActionTruncate {
			// EOF should only occur with truncation
			return tErrorf("read: unexpected EOF")
		}
		if err == ErrReadLimitExceeded && action != ReadLimitExceededActionError {
			// ErrReadLimitExceeded should only occur with ReadLimitExceededActionError
			return tErrorf("read: unexpected ErrReadLimitExceeded")
		}
		// Otherwise, fall through -- we still need to check that the data matches
	} else {
		if overflowed && action == ReadLimitExceededActionError {
			return tErrorf("read: should have gotten an error, but did not")
		}
	}
	expectedSize := size
	if overflowed {
		expectedSize = conn.BytesReadLimit - before
	}

	if conn.BytesRead != before+expectedSize {
		return tErrorf("check: BytesRead value inconsistent; expected %d, got %d", before+expectedSize, conn.BytesRead)
	}
	if len(ret) != expectedSize {
		return tErrorf("check: expected %d bytes, got %d", expectedSize, len(ret))
	}
	if expectedSize > 0 && !checkTestBuffer(ret) {
		return tErrorf("Got back invalid data (%x)", ret)
	}
	return nil
}

// Send size testBuffer bytes to conn, then perform a read, and return the result/error.
func sendReceive(t *testing.T, conn *TimeoutConnection, size int) ([]byte, error) {
	toSend := getTestBuffer(size)
	n, err := conn.Write(toSend)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
		return nil, err
	}
	if n != len(toSend) {
		t.Fatalf("Short write: expected to send %d bytes, returned %d", len(toSend), n)
		return nil, io.ErrShortWrite
	}
	readBuf := make([]byte, size)
	n, err = conn.Read(readBuf)
	return readBuf[0:n], err
}

// Get a size-byte slice of sequential bytes (mod 256), starting from 0
func getTestBuffer(size int) []byte {
	ret := make([]byte, size)
	for i := 0; i < size; i++ {
		ret[i] = byte(i & 0xff)
	}
	return ret
}

// Check that buf is of the type returned by getTestBuffer.
func checkTestBuffer(buf []byte) bool {
	if buf == nil || len(buf) == 0 {
		return false
	}
	for i, v := range buf {
		if v != byte(i&0xff) {
			return false
		}
	}
	return true
}

// Send / receive cfg.sendSize bytes in a single shot and check that it behaves appropriately.
func (cfg readLimitTestConfig) runSingleSend(t *testing.T, conn *TimeoutConnection, idx int) error {
	if err := checkedSendReceive(t, conn, cfg.sendSize); err != nil {
		return err
	}
	return nil
}

// Send / receive cfg.sendSize bytes, split over five sends, and check that it behaves appropriately.
func (cfg readLimitTestConfig) runMultiSend(t *testing.T, conn *TimeoutConnection, idx int) error {
	for i := 0; i < 5; i++ {
		if err := checkedSendReceive(t, conn, cfg.sendSize/5); err != nil {
			return err
		}
	}
	return nil
}

// A timeoutConnector that uses a dialer to dial the connections
type dialerConnector struct {
	readLimitTestConfig

	// This is lazily inited
	dialer *Dialer
}

// Function that returns a connector
type timeoutConnectorFactory func(readLimitTestConfig) timeoutConnector

// Dial the connection using the dialer (creating the dialer if necessary)
func (d *dialerConnector) connect(ctx context.Context, t *testing.T, port int, idx int) (*TimeoutConnection, error) {
	if d.dialer == nil {
		d.dialer = NewDialer(&Dialer{
			BytesReadLimit:          d.limit,
			ReadLimitExceededAction: d.action,
		})
	}
	var ret *TimeoutConnection
	conn, err := d.dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if conn != nil {
		ret = conn.(*TimeoutConnection)
	}
	return ret, err
}

func (d *dialerConnector) getConfig() readLimitTestConfig {
	return d.readLimitTestConfig
}

func dialerTimeoutConnectorFactory(cfg readLimitTestConfig) timeoutConnector {
	return &dialerConnector{
		readLimitTestConfig: cfg,
	}
}

// Dial using a direct call to DialTimeoutConnectionEx
type directDial struct {
	readLimitTestConfig
}

func (d *directDial) connect(ctx context.Context, t *testing.T, port int, idx int) (*TimeoutConnection, error) {
	conn, err := DialTimeoutConnectionEx("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second, time.Second, time.Second, time.Second, d.limit)
	var ret *TimeoutConnection
	if conn != nil {
		ret = conn.(*TimeoutConnection)
		ret.BytesReadLimit = d.limit
		ret.ReadLimitExceededAction = d.action
	}
	return ret, err
}

func (d *directDial) getConfig() readLimitTestConfig {
	return d.readLimitTestConfig
}

func directDialFactory(cfg readLimitTestConfig) timeoutConnector {
	return &directDial{cfg}
}

var readLimitTestConfigs = map[string]readLimitTestConfig{
	// Check that a 2000-byte read gets truncated at 1000 bytes
	"truncate": {
		limit:    1000,
		sendSize: 2000,
		action:   ReadLimitExceededActionTruncate,
	},

	// Check that a 1005-byte read gets truncated at 1000 bytes
	"truncate_close": {
		limit:    1000,
		sendSize: 1005,
		action:   ReadLimitExceededActionTruncate,
	},

	// Check that a 2000-byte read errors after reading the first 1000 bytes
	"error": {
		limit:    1000,
		sendSize: 2000,
		action:   ReadLimitExceededActionError,
	},

	// Check that a 2000-byte read panics after reading the first 1000 bytes
	"panic": {
		limit:    1000,
		sendSize: 2000,
		action:   ReadLimitExceededActionPanic,
	},

	// Check that the default settings pass (backwards compatibility)
	"default": {},

	// Check that a 100-byte read succeeds / is not truncated
	"happy": {
		limit:    1000,
		sendSize: 100,
		action:   ReadLimitExceededActionPanic,
	},

	// Check that a 1000-byte read succeeds / is not truncated
	"closeCall": {
		limit:    1000,
		sendSize: 1000,
		action:   ReadLimitExceededActionPanic,
	},
}

// Each of these gets run with each readLimitTestConfig
var connTestConnectors = map[string]timeoutConnectorFactory{
	"directDial":      directDialFactory,
	"dialerConnector": dialerTimeoutConnectorFactory,
}

// Run a single full trial with the given connector: connect, send/receive the configured bytes, and
// check that the response was properly truncated (or not), and that the bytes read total is
// correctly tabulated.
func runBytesReadLimitTrial(t *testing.T, connector timeoutConnector, idx int, method func(readLimitTestConfig, *testing.T, *TimeoutConnection, int) error) (result error) {
	cfg := connector.getConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := 0x1234 + idx
	runEchoServer(t, port)
	conn, err := connector.connect(ctx, t, port, idx)
	if err != nil {
		t.Fatalf("Error dialing: %v", err)
	}
	expectedSize := cfg.sendSize
	if expectedSize > cfg.limit {
		expectedSize = cfg.limit
	}
	defer func() {
		if conn.BytesRead != expectedSize {
			result = fmt.Errorf("BytesRead(%d) != expected(%d)", conn.BytesRead, expectedSize)
			t.Error(result)
		}
	}()
	defer conn.Close()
	return method(cfg, t, conn, idx)
}

// Run a full set of trials on the connector -- ten with a single send, and ten with multiple sends.
func testBytesReadLimitOn(t *testing.T, connector timeoutConnector) error {
	for i := 0; i < 10; i++ {
		if err := runBytesReadLimitTrial(t, connector, i, readLimitTestConfig.runSingleSend); err != nil {
			return err
		}
	}
	for i := 0; i < 10; i++ {
		if err := runBytesReadLimitTrial(t, connector, i, readLimitTestConfig.runMultiSend); err != nil {
			return err
		}
	}
	return nil
}

// Check that the BytesReadLimit is enforced (or not) as expected:
// 1. Create an echo server
// 2. Dial a fresh TimeoutConnection to the echo server with the given BytesReadLimit / ReadLimitExceededAction
// 3. Send the configured number of bytes in a single packet
// 4. Check that it (succeeds / truncates / errors / panics) according to the config
// 5. Repeat 10 times
// 6. Repeat the above 10 more times, except in #3, split the send across five packets
func TestBytesReadLimit(t *testing.T) {
	connectors := make(map[string]timeoutConnector)
	// Create a fresh connector for each configuration
	for cfgName, cfg := range readLimitTestConfigs {
		for connectorName, factory := range connTestConnectors {
			connectors[connectorName+"_"+cfgName] = factory(cfg)
		}
	}

	// Run each connector
	for name, connector := range connectors {
		t.Logf("Running %s", name)
		if err := testBytesReadLimitOn(t, connector); err != nil {
			t.Logf("Failed running %s: %v", name, err)
		}
	}
}
