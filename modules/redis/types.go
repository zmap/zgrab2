package redis

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
)

var (
	// ErrInvalidData is returned when the server returns data that cannot be
	// interpreted as a valid Redis value.
	ErrInvalidData = errors.New("invalid data")

	// ErrWrongType is returned when one identifier is expected but another is
	// found.
	ErrWrongType = errors.New("wrong type specifier")

	// ErrBadLength is returned when an invalid length value is found (e.g. a
	// negative length or longer than expected).
	ErrBadLength = errors.New("bad length")
)

// RedisType is a human readable type identifier for redis data
type RedisType string

const (
	// TypeSimpleString identifies Simple String (string) values
	TypeSimpleString RedisType = "simple string"

	// TypeError identifiers Error (string) values
	TypeError = "error"

	// TypeInteger identifiers Integer (int64) values
	TypeInteger = "integer"

	// TypeBulkString identifies Bulk String ([]byte) values
	TypeBulkString = "bulk string"

	// TypeArray identifies Array ([]RedisValue) types
	TypeArray = "array"
)

// RedisValue is implemented by any redis that can be returned by the server
type RedisValue interface {
	Type() RedisType
	Encode() []byte
}

// SimpleString type -- must not contain \r or \n. https://redis.io/topics/protocol#resp-simple-strings
type SimpleString string

// Type identifies this instance as a TypeSimpleString
func (SimpleString) Type() RedisType {
	return TypeSimpleString
}

// Encode returns the SimpleString encoding of the value ("+<string value>\r\n").
func (str SimpleString) Encode() []byte {
	return []byte("+" + str + "\r\n")
}

// ErrorMessage type -- a string, where the first word can optionally be
// interpreted as an error identifier.
// See https://redis.io/topics/protocol#resp-errors
type ErrorMessage string

// Type identifies this instance as a TypeError
func (ErrorMessage) Type() RedisType {
	return TypeError
}

// Encode returns the encoding of the error message ("-<error message>\r\n")
func (err ErrorMessage) Encode() []byte {
	return []byte("-" + err + "\r\n")
}

// ErrorPrefix returns the first word of the error message, which can be
// interpreted as a sort of error code.
func (err ErrorMessage) ErrorPrefix() string {
	serr := string(err)
	if len(serr) == 0 {
		return ""
	}
	return strings.SplitN(serr, " ", 2)[0]
}

// ErrorMessage returns the "message": if there is a prefix, return everything
// after it; otherwise, return the whole error string.
func (err ErrorMessage) ErrorMessage() string {
	parts := strings.SplitN(string(err), " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return string(err)
}

// Integer type -- an int64; "the returned integer is guaranteed to be in the
// range of a signed 64 bit integer"
// See https://redis.io/topics/protocol#resp-integers
type Integer int64

// Type identifies this instance as a TypeInteger
func (Integer) Type() RedisType {
	return TypeInteger
}

// Encode returns the encoding of the Integer value (":<base10Value>\r\n")
func (val Integer) Encode() []byte {
	return []byte(fmt.Sprintf(":%d\r\n", val))
}

// NullType -- a special type for the NullValue. Represented on the wire as a
// bulk string with -1 length.
type NullType []byte

// NullValue is a global NullType instance. Should not be used for comparisons
// (use IsNullValue).
var NullValue NullType = nil

// Type identifies the NullType instance as a TypeBulkString
func (NullType) Type() RedisType {
	return TypeBulkString
}

// Encode returns the null encoding (a bulk string with length = -1)
func (NullType) Encode() []byte {
	return []byte("$-1\r\n")
}

// IsNullValue checks if the value is the Redis NullValue (that is, it is a
// NullType)
func IsNullValue(data RedisValue) bool {
	_, ok := data.(NullType)
	return ok
}

// BulkString type -- a binary-safe string with a given length
type BulkString []byte

// Type identifies this instance as a BulkStringType
func (BulkString) Type() RedisType {
	return TypeBulkString
}

// Encode returns the encoding of this value ("$<base10Length>\r\n<value>\r\n")
func (str BulkString) Encode() []byte {
	prefix := fmt.Sprintf("$%d\r\n", len(str))
	ret := make([]byte, len(prefix)+len(str)+2)
	copy(ret, []byte(prefix))
	copy(ret[len(prefix):], str)
	ret[len(ret)-2] = '\r'
	ret[len(ret)-1] = '\n'
	return ret
}

// RedisArray type -- an array of other RedisValues.
// See https://redis.io/topics/protocol#resp-arrays
type RedisArray []RedisValue

// Type identifies this instance as a TypeArray
func (RedisArray) Type() RedisType {
	return TypeArray
}

// Encode returns the encoding of the array, e.g.
// "*<base10Size>\r\n<element 1><element 2>..."
func (array RedisArray) Encode() []byte {
	var ret []byte
	prefix := fmt.Sprintf("*%d\r\n", len(array))
	ret = append(ret, []byte(prefix)...)
	for _, item := range array {
		ret = append(ret, item.Encode()...)
	}
	return ret
}

// read reads the next n bytes from the connection, using the read buffer if
// available
func (conn *Connection) read(n int) ([]byte, error) {
	for len(conn.buffer) < n {
		r, err := conn.rawRead()
		if err != nil {
			return nil, err
		}
		conn.buffer = append(conn.buffer, r...)
	}
	ret, rest := conn.buffer[0:n], conn.buffer[n:]
	conn.buffer = rest
	return ret, nil
}

// rawRead reads the next chunk of data from the wire, without using the buffer
func (conn *Connection) rawRead() ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := conn.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// readUntilCRLF reads data from the connection until it hits a CRLF (\r\n).
// The data up to (but not including) the CRLF is returned, and the next byte
// read will be the first byte after the LF.
func (conn *Connection) readUntilCRLF() ([]byte, error) {
	idx := bytes.Index(conn.buffer, []byte{'\r', '\n'})
	for ; idx == -1; idx = bytes.Index(conn.buffer, []byte{'\r', '\n'}) {
		ret, err := conn.rawRead()
		if err != nil {
			return nil, err
		}
		conn.buffer = append(conn.buffer, ret...)
	}
	ret := conn.buffer[:idx]
	conn.buffer = conn.buffer[idx+2:]
	return ret, nil
}

// readBulkString reads a BulkString from the connection, assuming that the
// type identifier ("$") has already been consumed.
// The BulkString is returned, and the next read will start at the first byte
// after the final LF.
func (conn *Connection) readBulkString() (RedisValue, error) {
	_size, err := conn.readInteger()
	if err != nil {
		return nil, err
	}
	size := _size.(Integer)
	if size == -1 {
		return NullValue, nil
	}
	if size < 0 || size > 512*1024*1024 {
		return nil, ErrBadLength
	}
	truncSize := int(size) + 2
	body, err := conn.read(truncSize)
	if err != nil {
		return nil, err
	}
	if !(body[size] == '\r' && body[size+1] == '\n') {
		return nil, ErrInvalidData
	}
	return BulkString(body[:size]), nil
}

// readSimpleString reads a SimpleString from the connection, assuming that
// the type identifier ("+") has already been consumed.
// The SimpleString is returned, and the next read will start at the first byte
// following the terminal LF.
func (conn *Connection) readSimpleString() (RedisValue, error) {
	body, err := conn.readUntilCRLF()
	if err != nil {
		return nil, err
	}
	return SimpleString(body), nil
}

// readInt reads a decimal integer terminated by a CRLF from the connection.
// If the data can be decoded as an int64 it is returned, otherwise an error is
// returned.
func (conn *Connection) readInt() (int64, error) {
	ret, err := conn.readSimpleString()
	if err != nil {
		return -1, err
	}
	parsed, err := strconv.ParseInt(string(ret.(SimpleString)), 10, 64)
	if err != nil {
		return -1, ErrInvalidData
	}
	return parsed, nil
}

// readInteger reads an Integer from the connection, assuming that the type
// identifier (":") has already been consumed.
// The Integer is returned, and the next read will start at the first byte
// following the terminal LF.
// Returns an error if the data cannot be parsed as an integer.
func (conn *Connection) readInteger() (RedisValue, error) {
	ret, err := conn.readInt()
	if err != nil {
		return nil, err
	}
	return Integer(ret), nil
}

// readErrorMessage reads an ErrorMessage from the connection, assuming that the
// type identifier ("-") has already been consumed.
// The ErrorMessage is returned, and the next read will start at the first byte
// following the terminal LF.
func (conn *Connection) readErrorMessage() (RedisValue, error) {
	body, err := conn.readUntilCRLF()
	if err != nil {
		return nil, err
	}
	return ErrorMessage(body), nil
}

// readRedisArray reads a RedisArray from the connection, assuming that the
// type identifier ("*") has already been consumed.
// The array is returned, and the next read will start at the first byte
// following the terminal LF of the array's terminal element.
func (conn *Connection) readRedisArray() (RedisValue, error) {
	numElements, err := conn.readInt()
	if err != nil {
		return nil, err
	}
	ret := make(RedisArray, numElements)
	var i int64
	for i = 0; i < numElements; i++ {
		ret[i], err = conn.ReadRedisValue()
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

// redisDataReader is a function that reads a RedisValue from a connection.
type redisDataReader func(*Connection) (RedisValue, error)

// readers is a map of type identifier character to the reader for that type
var readers map[byte]redisDataReader

// Connection holds the state for a single connection within a scan
type Connection struct {
	scanner *Scanner
	conn    net.Conn
	buffer  []byte
	isSSL   bool
}

// write writes data to the connection, and returns an error if the write fails
// or if not all of the data is written.
func (conn *Connection) write(data []byte) error {
	n, err := conn.conn.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return &zgrab2.ScanError{Status: zgrab2.SCAN_CONNECTION_CLOSED, Err: nil}
	}
	return nil
}

// inlineQuote quotes arg if it contains any spaces, for use in inline commands.
func inlineQuote(arg string) string {
	if strings.ContainsAny(arg, " ") {
		return "\"" + arg + "\""
	}
	return arg
}

// getInlineCommand gets the inline version of the given command+args: any
// elements containing spaces are quoted, and the elements are joined together
// with spaces.
func getInlineCommand(cmd string, args ...string) string {
	ret := make([]string, len(args)+1)
	ret[0] = inlineQuote(cmd)
	for i, v := range args {
		ret[i+1] = inlineQuote(v)
	}
	return strings.Join(ret, " ")
}

// SendInlineCommand sends the given command with the inline encoding, and then
// reads/returns the server's response.
func (conn *Connection) SendInlineCommand(cmd string, args ...string) (RedisValue, error) {
	out := getInlineCommand(cmd, args...) + "\r\n"
	if err := conn.write([]byte(out)); err != nil {
		return nil, err
	}
	return conn.ReadRedisValue()
}

// SendCommand sends the given command+args to the server, then reads/returns
// the server's response.
func (conn *Connection) SendCommand(cmd string, args ...string) (RedisValue, error) {
	array := make(RedisArray, len(args)+1)
	array[0] = BulkString(cmd)
	for i, v := range args {
		array[i+1] = BulkString(v)
	}
	if err := conn.WriteRedisValue(array); err != nil {
		return nil, err
	}
	return conn.ReadRedisValue()
}

// WriteRedisValue writes the encoded value to the connection.
func (conn *Connection) WriteRedisValue(value RedisValue) error {
	encoded := value.Encode()
	return conn.write(encoded)
}

// ReadRedisValue reads a RedisValue of any type from the connection. The next
// read will return the first byte following the value's terminal LF.
// If the first byte is not a recognized type identifier, ErrInvalidData
// is returned.
func (conn *Connection) ReadRedisValue() (RedisValue, error) {
	if readers == nil {
		readers = map[byte]redisDataReader{
			'+': func(conn *Connection) (RedisValue, error) { return conn.readSimpleString() },
			':': func(conn *Connection) (RedisValue, error) { return conn.readInteger() },
			'-': func(conn *Connection) (RedisValue, error) { return conn.readErrorMessage() },
			'$': func(conn *Connection) (RedisValue, error) { return conn.readBulkString() },
			'*': func(conn *Connection) (RedisValue, error) { return conn.readRedisArray() },
		}
	}
	v, err := conn.read(1)
	if err != nil {
		return nil, err
	}
	ch := v[0]
	reader, ok := readers[ch]
	if !ok {
		return nil, ErrInvalidData
	}
	return reader(conn)
}

func (conn *Connection) GetTLSLog() *zgrab2.TLSLog {
	if !conn.isSSL {
		return nil
	}
	return conn.conn.(*zgrab2.TLSConnection).GetLog()
}

type CustomResponse struct {
	Command   string `json:"command,omitempty"`
	Arguments string `json:"arguments,omitempty"`
	Response  string `json:"response,omitempty"`
}
