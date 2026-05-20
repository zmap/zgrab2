package redis

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

// newTestConnection creates a Connection backed by a net.Pipe.
// Write data to the returned writer, then call ReadRedisValue on the connection.
// Close the writer when done feeding data.
func newTestConnection(data []byte) (*Connection, net.Conn) {
	server, client := net.Pipe()
	conn := &Connection{conn: client}
	go func() {
		server.Write(data)
		server.Close()
	}()
	return conn, client
}

func TestReadRedisArray_NegativeLength(t *testing.T) {
	// *-5\r\n — negative element count must be rejected
	data := []byte("*-5\r\n")
	conn, client := newTestConnection(data)
	defer client.Close()

	_, err := conn.ReadRedisValue()
	if err == nil {
		t.Fatal("expected error for negative array length, got nil")
	}
	if !errors.Is(err, ErrBadLength) {
		t.Fatalf("expected ErrBadLength, got: %v", err)
	}
}

func TestReadRedisArray_ZeroLength(t *testing.T) {
	// *0\r\n — empty array is valid
	data := []byte("*0\r\n")
	conn, client := newTestConnection(data)
	defer client.Close()

	val, err := conn.ReadRedisValue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	arr, ok := val.(RedisArray)
	if !ok {
		t.Fatalf("expected RedisArray, got %T", val)
	}
	if len(arr) != 0 {
		t.Fatalf("expected empty array, got %d elements", len(arr))
	}
}

func TestReadRedisArray_ValidSmall(t *testing.T) {
	// *2\r\n+hello\r\n+world\r\n
	data := []byte("*2\r\n+hello\r\n+world\r\n")
	conn, client := newTestConnection(data)
	defer client.Close()

	val, err := conn.ReadRedisValue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	arr, ok := val.(RedisArray)
	if !ok {
		t.Fatalf("expected RedisArray, got %T", val)
	}
	if len(arr) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(arr))
	}
}

func TestReadRedisArray_ExceedsMaxElements(t *testing.T) {
	// Array count exceeding maxArrayElements must be rejected
	data := []byte(fmt.Sprintf("*%d\r\n", maxArrayElements+1))
	conn, client := newTestConnection(data)
	defer client.Close()

	_, err := conn.ReadRedisValue()
	if err == nil {
		t.Fatal("expected error for oversized array, got nil")
	}
	if !errors.Is(err, ErrBadLength) {
		t.Fatalf("expected ErrBadLength, got: %v", err)
	}
}

func TestReadRedisArray_ExactlyMaxElements(t *testing.T) {
	// maxArrayElements count should be accepted (not rejected).
	// We can't actually feed 1M elements, so just verify the count is parsed
	// without ErrBadLength by checking it tries to read the first element
	// and fails with an I/O error (not ErrBadLength).
	data := []byte(fmt.Sprintf("*%d\r\n", maxArrayElements))
	conn, client := newTestConnection(data)
	defer client.Close()

	_, err := conn.ReadRedisValue()
	if err == nil {
		t.Fatal("expected error (no element data), got nil")
	}
	// Should NOT be ErrBadLength — the count is accepted; it fails reading elements
	if errors.Is(err, ErrBadLength) {
		t.Fatal("maxArrayElements should be accepted, not rejected as ErrBadLength")
	}
}

func TestReadRedisArray_HugeCount(t *testing.T) {
	// Simulates a malicious server sending *999999999\r\n
	data := []byte("*999999999\r\n")
	conn, client := newTestConnection(data)
	defer client.Close()

	_, err := conn.ReadRedisValue()
	if err == nil {
		t.Fatal("expected error for huge array count, got nil")
	}
	if !errors.Is(err, ErrBadLength) {
		t.Fatalf("expected ErrBadLength, got: %v", err)
	}
}

func TestReadRedisValue_MaxDepthExceeded(t *testing.T) {
	// Build nested arrays deeper than maxRecursionDepth.
	// Each level: *1\r\n (one-element array wrapping the next)
	// Final level: +ok\r\n
	var data []byte
	for i := 0; i <= maxRecursionDepth+1; i++ {
		data = append(data, []byte("*1\r\n")...)
	}
	data = append(data, []byte("+ok\r\n")...)

	conn, client := newTestConnection(data)
	defer client.Close()

	val, err := conn.ReadRedisValue()
	if err == nil {
		t.Fatal("expected ErrMaxDepthExceeded, got nil")
	}
	if !errors.Is(err, ErrMaxDepthExceeded) {
		t.Fatalf("expected ErrMaxDepthExceeded, got: %v", err)
	}
	// Should still return partial data — the outer arrays that were collected
	if val == nil {
		t.Fatal("expected partial data to be returned along with the error")
	}
	arr, ok := val.(RedisArray)
	if !ok {
		t.Fatalf("expected RedisArray partial result, got %T", val)
	}
	// The outermost array should have 0 elements (its only child errored)
	if len(arr) != 0 {
		t.Fatalf("expected 0-element partial array at top level, got %d", len(arr))
	}
}

func TestReadRedisValue_DepthExactlyAtLimit(t *testing.T) {
	// Nest exactly maxRecursionDepth levels — should succeed.
	// depth starts at 0, each *1\r\n adds 1 depth.
	// At depth == maxRecursionDepth, non-array types still work.
	var data []byte
	for i := 0; i < maxRecursionDepth; i++ {
		data = append(data, []byte("*1\r\n")...)
	}
	data = append(data, []byte("+ok\r\n")...)

	conn, client := newTestConnection(data)
	defer client.Close()

	val, err := conn.ReadRedisValue()
	if err != nil {
		t.Fatalf("nesting at exactly maxRecursionDepth should succeed, got: %v", err)
	}
	// Unwrap the nested arrays to find the inner value
	current := val
	for i := 0; i < maxRecursionDepth; i++ {
		arr, ok := current.(RedisArray)
		if !ok {
			t.Fatalf("level %d: expected RedisArray, got %T", i, current)
		}
		if len(arr) != 1 {
			t.Fatalf("level %d: expected 1 element, got %d", i, len(arr))
		}
		current = arr[0]
	}
	ss, ok := current.(SimpleString)
	if !ok {
		t.Fatalf("innermost value: expected SimpleString, got %T", current)
	}
	if string(ss) != "ok" {
		t.Fatalf("innermost value: expected 'ok', got '%s'", string(ss))
	}
}

func TestReadRedisValue_NestedArrayValid(t *testing.T) {
	// *2\r\n*1\r\n+a\r\n+b\r\n — [[a], b] — 2 levels deep, should work
	data := []byte("*2\r\n*1\r\n+a\r\n+b\r\n")
	conn, client := newTestConnection(data)
	defer client.Close()

	val, err := conn.ReadRedisValue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	arr, ok := val.(RedisArray)
	if !ok || len(arr) != 2 {
		t.Fatalf("expected 2-element array, got %T", val)
	}
	inner, ok := arr[0].(RedisArray)
	if !ok || len(inner) != 1 {
		t.Fatalf("expected 1-element inner array")
	}
	if string(inner[0].(SimpleString)) != "a" {
		t.Fatal("expected inner value 'a'")
	}
	if string(arr[1].(SimpleString)) != "b" {
		t.Fatal("expected outer value 'b'")
	}
}

func TestReadRedisArray_PartialDataOnError(t *testing.T) {
	// *3\r\n+a\r\n+b\r\n — array expects 3 elements but connection closes after 2
	// Should return the 2 collected elements along with the error
	data := []byte("*3\r\n+a\r\n+b\r\n")
	conn, client := newTestConnection(data)
	defer client.Close()

	val, err := conn.ReadRedisValue()
	if err == nil {
		t.Fatal("expected error for incomplete array, got nil")
	}
	if val == nil {
		t.Fatal("expected partial data to be returned with the error")
	}
	arr, ok := val.(RedisArray)
	if !ok {
		t.Fatalf("expected RedisArray, got %T", val)
	}
	if len(arr) != 2 {
		t.Fatalf("expected 2 collected elements, got %d", len(arr))
	}
	if string(arr[0].(SimpleString)) != "a" {
		t.Fatal("expected first element 'a'")
	}
	if string(arr[1].(SimpleString)) != "b" {
		t.Fatal("expected second element 'b'")
	}
}

func TestReadRedisValue_NonArrayTypes(t *testing.T) {
	// Verify non-array types still work after refactor
	tests := []struct {
		name string
		data []byte
		typ  RedisType
	}{
		{"SimpleString", []byte("+OK\r\n"), TypeSimpleString},
		{"Error", []byte("-ERR unknown\r\n"), TypeError},
		{"Integer", []byte(":42\r\n"), TypeInteger},
		{"BulkString", []byte("$5\r\nhello\r\n"), TypeBulkString},
		{"NullBulkString", []byte("$-1\r\n"), TypeBulkString},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, client := newTestConnection(tt.data)
			defer client.Close()

			val, err := conn.ReadRedisValue()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if val.Type() != tt.typ {
				t.Fatalf("expected type %s, got %s", tt.typ, val.Type())
			}
		})
	}
}
