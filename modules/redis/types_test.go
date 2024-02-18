package redis

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeIO is a simple fake Reader/Writer. Read pulls data from the output
// channel; Writes are NOOPs.
type fakeIO struct {
	output chan byte
}

// Read from output until it would block.
func (fakeio *fakeIO) Read(buf []byte) (int, error) {
	// read what can be read from the channel without blocking
	for i := 0; i < len(buf); {
		select {
		case b := <-fakeio.output:
			buf[i] = b
			i++
		default:
			return i, nil
		}
	}
	return len(buf), nil
}

// Write does nothing.
func (fakeio *fakeIO) Write(buf []byte) (int, error) {
	return len(buf), nil
}

// Provide data to the output channel.
func (fakeio *fakeIO) Provide(buf []byte) {
	go func() {
		// send new bytes as the buffer clears
		for _, v := range buf {
			fakeio.output <- v
		}
	}()
}

func (fakeio *fakeIO) Close() error {
	return nil
}

func (fakeio *fakeIO) LocalAddr() net.Addr {
	return fakeAddr{}
}

func (fakeio *fakeIO) RemoteAddr() net.Addr {
	return fakeAddr{}
}

func (fakeio *fakeIO) SetDeadline(t time.Time) error {
	return nil
}

func (fakeio *fakeIO) SetReadDeadline(t time.Time) error {
	return nil
}

func (fakeio *fakeIO) SetWriteDeadline(t time.Time) error {
	return nil
}

// A fake net.Addr
type fakeAddr struct{}

func (f fakeAddr) Network() string {
	return "tcp"
}

func (f fakeAddr) String() string {
	return "127.0.0.1"
}

var bigSimpleString = strings.Repeat("simple,", 1024*1024)
var bigBulkString = "--- BEGIN BULK STRING ---\r\n" + bigSimpleString + "\r\n--- END BULK STRING---\r\n"

// simpleStrings maps the string value to its encoding
var simpleStrings = map[string]string{
	"":                 "+\r\n",
	"foo":              "+foo\r\n",
	"0123456789abcdef": "+0123456789abcdef\r\n",
	bigSimpleString:    "+" + bigSimpleString + "\r\n",
}

// bulkStrings maps the string value to its encoding
var bulkStrings = map[string]string{
	"":                 "$0\r\n\r\n",
	"foo":              "$3\r\nfoo\r\n",
	"0123456789abcdef": "$16\r\n0123456789abcdef\r\n",
	bigBulkString:      fmt.Sprintf("$%d\r\n%s\r\n", len(bigBulkString), bigBulkString),
	"\r\n\n\r\r\n":     "$6\r\n\r\n\n\r\r\n\r\n",
}

// integers maps integer values to their encoding
var integers = map[int64]string{
	0:  ":0\r\n",
	1:  ":1\r\n",
	-1: ":-1\r\n",
	// Largest signed 64-bit integer
	(1 << 63) - 1: ":9223372036854775807\r\n",
	// Smallest signed 64-bit integer
	-(1 << 63): ":-9223372036854775808\r\n",
	12345:      ":12345\r\n",
}

// redisErrors maps error strings to their encoding
var redisErrors = map[string]string{
	"":                         "-\r\n",
	"ERR something went wrong": "-ERR something went wrong\r\n",
	"singleword":               "-singleword\r\n",
}

// redisErrors maps error strings to their prefixes
var redisErrorPrefixes = map[string]string{
	"":                         "",
	"ERR something went wrong": "ERR",
	"singleword":               "singleword",
}

// redisErrorMessages maps error strings to their "messages"
var redisErrorMessages = map[string]string{
	"":                         "",
	"ERR something went wrong": "something went wrong",
	"singleword":               "singleword",
}

// redisArrays maps encoded array values to the corresponding array (Note: reverse key/value order from other maps)
var redisArrays = map[string]RedisArray{
	"*0\r\n":      RedisArray{},
	"*1\r\n+\r\n": RedisArray{SimpleString("")},
	"*2\r\n*1\r\n*0\r\n*1\r\n$5\r\n12345\r\n": RedisArray{RedisArray{RedisArray{}}, RedisArray{BulkString("12345")}},
	"*5\r\n" +
		"+simpleString\r\n" +
		"-ERR error message\r\n" +
		":12345\r\n" +
		"$47\r\n*5\r\n+simpleString\r\n-ERR error message\r\n:12345\r\n\r\n" +
		"*0\r\n": RedisArray{
		SimpleString("simpleString"),
		ErrorMessage("ERR error message"),
		Integer(12345),
		BulkString([]byte("*5\r\n+simpleString\r\n-ERR error message\r\n:12345\r\n")),
		RedisArray{},
	},
}

// getConnection backed by a fakeIO, and the fakeIO instance.
func getConnection() (*Connection, *fakeIO) {
	fakeio := fakeIO{
		output: make(chan byte, 1024),
	}
	conn := Connection{conn: &fakeio}
	return &conn, &fakeio
}

// strip s down to 32 chars
func strip(s interface{}) string {
	var stringVal string
	switch v := s.(type) {
	case SimpleString:
		stringVal = string(v)
	case string:
		stringVal = v
	case BulkString:
		stringVal = string([]byte(v))
	case []byte:
		stringVal = string(v)
	default:
		stringVal = fmt.Sprintf("%v", s)
	}
	if len(stringVal) > 32 {
		return stringVal[0:20] + "..." + stringVal[len(stringVal)-10:]
	}
	return stringVal
}

// Check that the two strings are equivalent, and if not, log the expected/actual
func assertEquals(t *testing.T, actual string, expected string) {
	if actual != expected {
		t.Errorf("Expected [<%s>], got [<%s>]", strip(expected), strip(actual))
	}
}

// Read a value from the connection, or throw a fatal error
func rawRead(t *testing.T, conn *Connection) RedisValue {
	ret, err := conn.ReadRedisValue()
	if err != nil {
		t.Fatalf("Error reading value: %v", err)
	}
	return ret
}

// Read a value from the connection and convert it to a string for easy comparison
func read(t *testing.T, conn *Connection) string {
	ret := rawRead(t, conn)
	b, ok := ret.(BulkString)
	if ok {
		return string(b)
	}
	return fmt.Sprintf("%v", ret)
}

// Encode a value and return a string for easy comparison
func encode(a RedisValue) string {
	return string(a.Encode())
}

// Recursively compare two arrays, with the given path prefix
func _compareArrays(a, b RedisArray, path string) error {
	if len(a) != len(b) {
		return fmt.Errorf("Length mismatch (%d != %d)", len(a), len(b))
	}
	for i, ai := range a {
		subPath := fmt.Sprintf("%s[%d]", path, i)
		bi := b[i]
		aType := reflect.TypeOf(ai)
		bType := reflect.TypeOf(bi)
		if aType != bType {
			return fmt.Errorf("Type mismatch at %s: %s != %s", subPath, aType.Name(), bType.Name())
		}
		switch ait := ai.(type) {
		case RedisArray:
			if err := _compareArrays(ait, bi.(RedisArray), subPath); err != nil {
				return err
			}
		case BulkString:
			if !bytes.Equal(ait, bi.(BulkString)) {
				return fmt.Errorf("Bulk string mismatch at %s: %s != %s", subPath, strip(ai), strip(bi))
			}
		default:
			if ai != bi {
				return fmt.Errorf("Mismatch at %s: %s != %s", subPath, strip(ai), strip(bi))
			}
		}
	}
	return nil
}

// Compare two RedisValues directly (without using their encodings)
func compareRedisValues(a, b RedisValue) error {
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return fmt.Errorf("different types (%s != %s)", reflect.TypeOf(a).Name(), reflect.TypeOf(b).Name())
	}
	switch c := a.(type) {
	case RedisArray:
		return compareArrays(c, b.(RedisArray))
	case BulkString:
		if !bytes.Equal(c, b.(BulkString)) {
			return fmt.Errorf("byte array mismatch (%s != %s)", strip(a), strip(b))
		}
		return nil
	case NullType:
		return nil
	case Integer:
		if int64(c) != int64(b.(Integer)) {
			return fmt.Errorf("int mismatch (%d != %d)", c, int64(b.(Integer)))
		}
		return nil
	default:
		if fmt.Sprintf("%v", a) != fmt.Sprintf("%v", b) {
			return fmt.Errorf("Generic mismatch (%s != %s)", strip(a), strip(b))
		}
		return nil
	}
}

// Push the encoding to the fake IO, then read it off and compare it to the expected value
func writeThenRead(t *testing.T, conn *Connection, io *fakeIO, encoded string, expected RedisValue) {
	assertEquals(t, encoded, encode(expected))
	io.Provide([]byte(encoded))
	decoded, err := conn.ReadRedisValue()
	if err != nil {
		t.Fatalf("Error decoding value for %s: %v", strip(string(encoded)), err)
	}
	if err = compareRedisValues(decoded, expected); err != nil {
		t.Errorf("Read value did not match original value: %s != %s: %v", strip(decoded), strip(expected), err)
	}
}

// TestSimpleString checks that SimpleStrings are encoded/decoded as expected.
func TestSimpleString(t *testing.T) {
	conn, io := getConnection()
	for str, encoding := range simpleStrings {
		writeThenRead(t, conn, io, encoding, SimpleString(str))
	}
}

// TestInteger checks that Integers are encoded/decoded to the expected values.
func TestInteger(t *testing.T) {
	conn, io := getConnection()
	for val, encoding := range integers {
		writeThenRead(t, conn, io, encoding, Integer(val))
	}
}

// TestBulkString checks that SimpleStrings are encoded/decoded as expected.
func TestBulkString(t *testing.T) {
	conn, io := getConnection()
	for str, encoding := range bulkStrings {
		writeThenRead(t, conn, io, encoding, BulkString([]byte(str)))
	}
	writeThenRead(t, conn, io, "$-1\r\n", NullValue)
}

// TestIsNullValue checks that only the null value causes IsNullValue to return true
func TestIsNullValue(t *testing.T) {
	if !IsNullValue(NullValue) {
		t.Errorf("!IsNullValue(&global RedisNull)")
	}
	for str, array := range redisArrays {
		if IsNullValue(array) {
			t.Errorf("Non-null array '%s' returned IsNullValue", strip(str))
		}
	}
	for err := range redisErrors {
		if IsNullValue(ErrorMessage(err)) {
			t.Errorf("Non-null error message '%s' returned IsNullValue", strip(err))
		}
	}
	for val := range integers {
		if IsNullValue(Integer(val)) {
			t.Errorf("Non-null integer '%d' returned IsNullValue", val)
		}
	}
	for str := range bulkStrings {
		bulk := BulkString([]byte(str))
		if IsNullValue(bulk) {
			t.Errorf("Non-null bulk string '%s' returned IsNullValue", strip(str))
		}
	}
	for str := range simpleStrings {
		if IsNullValue(SimpleString(str)) {
			t.Errorf("Non-null simple string '%s' returned IsNullValue", strip(str))
		}
	}
}

// TestErrorMessage checks that ErrorMessages are encoded/decoded as expected.
func TestErrorMessage(t *testing.T) {
	conn, io := getConnection()
	for str, encoding := range redisErrors {
		assertEquals(t, ErrorMessage(str).ErrorPrefix(), redisErrorPrefixes[str])
		assertEquals(t, ErrorMessage(str).ErrorMessage(), redisErrorMessages[str])
		writeThenRead(t, conn, io, encoding, ErrorMessage(str))
	}
}

// compareArrays recursively compares two arrays (loops not supported)
func compareArrays(a, b RedisArray) error {
	return _compareArrays(a, b, "")
}

// TestRedisArray checks that RedisArray encoding and decoding match the expected values.
func TestRedisArray(t *testing.T) {
	conn, io := getConnection()

	// Slowly build up array, checking its encoding after each element is added
	var array RedisArray
	e0 := SimpleString("foo")
	e1 := BulkString([]byte(bigBulkString))
	e2 := Integer(0)
	e3 := Integer((1 << 62))
	e4 := make(RedisArray, 0)
	e5 := ErrorMessage("ERR some error")
	writeThenRead(t, conn, io, "*0\r\n", array)
	array = append(array, e0)
	writeThenRead(t, conn, io, "*1\r\n"+encode(e0), array)
	array = append(array, e1)
	writeThenRead(t, conn, io, "*2\r\n"+encode(e0)+encode(e1), array)
	array = append(array, e2)
	writeThenRead(t, conn, io, "*3\r\n"+encode(e0)+encode(e1)+encode(e2), array)
	array = append(array, e3)
	writeThenRead(t, conn, io, "*4\r\n"+encode(e0)+encode(e1)+encode(e2)+encode(e3), array)
	array = append(array, e4)
	writeThenRead(t, conn, io, "*5\r\n"+encode(e0)+encode(e1)+encode(e2)+encode(e3)+encode(e4), array)
	array = append(array, e5)
	writeThenRead(t, conn, io, "*6\r\n"+encode(e0)+encode(e1)+encode(e2)+encode(e3)+encode(e4)+encode(e5), array)

	// Check calculated values
	for expectedEncoding, redisValue := range redisArrays {
		writeThenRead(t, conn, io, expectedEncoding, redisValue)
	}
}
