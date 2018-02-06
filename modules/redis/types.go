package redis

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"encoding/json"

	"github.com/zmap/zgrab2"
)

type RedisType string

const (
	TypeSimpleString RedisType = "simple string"
	TypeError                  = "error"
	TypeInteger                = "integer"
	TypeBulkString             = "bulk string"
	TypeArray                  = "array"
)

type RedisValue interface {
	Type() RedisType
	Encode() []byte
}

// Must not contain \r or \n. https://redis.io/topics/protocol#resp-simple-strings
type SimpleString string

func (SimpleString) Type() RedisType {
	return TypeSimpleString
}

func (str SimpleString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(str))
}

func (str SimpleString) Encode() []byte {
	return []byte("+" + str + "\r\n")
}

// https://redis.io/topics/protocol#resp-errors
type ErrorMessage string

type ErrorMessageJSON struct {
	Error string `json:"error"`
}

func (ErrorMessage) Type() RedisType {
	return TypeError
}

func (err ErrorMessage) MarshalJSON() ([]byte, error) {
	return json.Marshal(ErrorMessageJSON{
		Error: string(err),
	})
}

func (err ErrorMessage) Encode() []byte {
	return []byte("-" + err + "\r\n")
}

func (err ErrorMessage) ErrorPrefix() string {
	return strings.SplitN(string(err), " ", 2)[0]
}

func (err ErrorMessage) ErrorMessage() string {
	parts := strings.SplitN(string(err), " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return string(err)
}

// "the returned integer is guaranteed to be in the range of a signed 64 bit integer" (https://redis.io/topics/protocol#resp-integers)
type Integer int64

func (Integer) Type() RedisType {
	return TypeInteger
}

func (val Integer) MarshalJSON() ([]byte, error) {
	return json.Marshal(int64(val))
}

func (val Integer) Encode() []byte {
	return []byte(fmt.Sprintf(":%d\r\n", val))
}

type NullType []byte

var NullValue NullType = nil

func (NullType) Type() RedisType {
	return TypeBulkString
}

func (NullType) MarshalJSON() ([]byte, error) {
	return json.Marshal(nil)
}

func (NullType) Encode() []byte {
	return []byte("$-1\r\n")
}

func IsNullValue(data RedisValue) bool {
	/*
	   if data == nil {
	       // the pointer might point to nil, but the pointer itself shouldn't be nil
	       return false
	   }
	*/
	_, ok := data.(NullType)
	return ok
}

type BulkString []byte

func (BulkString) Type() RedisType {
	return TypeBulkString
}

func (str BulkString) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(str))
}

func (str BulkString) Encode() []byte {
	prefix := fmt.Sprintf("$%d\r\n", len(str))
	ret := make([]byte, len(prefix)+len(str)+2)
	copy(ret, []byte(prefix))
	copy(ret[len(prefix):], str)
	ret[len(ret)-2] = '\r'
	ret[len(ret)-1] = '\n'
	return ret
}

// https://redis.io/topics/protocol#resp-arrays
type RedisArray []RedisValue

func (RedisArray) Type() RedisType {
	return TypeArray
}

func (array RedisArray) Encode() []byte {
	var ret []byte
	prefix := fmt.Sprintf("*%d\r\n", len(array))
	ret = append(ret, []byte(prefix)...)
	for _, item := range array {
		ret = append(ret, item.Encode()...)
	}
	return ret
}

// RedisScanResults is the output of the scan.
type RedisScanResults struct {
	infoResponse string
	// TODO: Add protocol

	// Protocols that support TLS should include
	// TLSLog      *zgrab2.TLSLog `json:"tls,omitempty"`
}

var (
	ErrRedisInvalidData = errors.New("invalid data")
	ErrRedisWrongType   = errors.New("wrong type specifier")
	ErrRedisBadLength   = errors.New("bad length")
)

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

func (conn *Connection) rawRead() ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := conn.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

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

func basicRedisDecode(id byte, msg []byte) (string, []byte, error) {
	if msg[0] != id {
		return "", nil, ErrRedisWrongType
	}
	str := string(msg)
	idx := strings.Index(str, "\r\n")
	if idx == -1 {
		return "", nil, ErrRedisInvalidData
	}
	return string(msg[1:idx]), msg[idx+2:], nil
}

func intRedisDecode(id byte, msg []byte) (int64, []byte, error) {
	ret, rest, err := basicRedisDecode(id, msg)
	if err != nil {
		return 0, nil, err
	}
	parsed, err := strconv.ParseInt(ret, 10, 64)
	if err != nil {
		return 0, nil, ErrRedisInvalidData
	}
	return parsed, rest, nil
}

func (conn *Connection) readResponse() (RedisValue, error) {
	return nil, nil
}

func decodeBulkString(msg []byte) (RedisValue, []byte, error) {
	size, rest, err := intRedisDecode('$', msg)
	if err != nil {
		return nil, nil, err
	}
	if size == -1 {
		return NullValue, rest, nil
	}
	if int64(len(rest)) < size+2 {
		return nil, nil, ErrRedisInvalidData
	}
	if rest[size] != '\r' || rest[size+1] != '\n' {
		return nil, nil, ErrRedisInvalidData
	}
	return BulkString(rest[0:size]), rest[size+2:], nil
}

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
		return nil, ErrRedisBadLength
	}
	truncSize := int(size) + 2
	body, err := conn.read(truncSize)
	if err != nil {
		return nil, err
	}
	if !(body[size] == '\r' && body[size+1] == '\n') {
		return nil, ErrRedisInvalidData
	}
	return BulkString(body[:size]), nil
}

func decodeSimpleString(msg []byte) (RedisValue, []byte, error) {
	ret, rest, err := basicRedisDecode('+', msg)
	if err != nil {
		return nil, nil, err
	}
	return SimpleString(ret), rest, err
}

func (conn *Connection) readSimpleString() (RedisValue, error) {
	body, err := conn.readUntilCRLF()
	if err != nil {
		return nil, err
	}
	return SimpleString(body), nil
}

func decodeInteger(msg []byte) (RedisValue, []byte, error) {
	ret, rest, err := intRedisDecode(':', msg)
	if err != nil {
		return nil, nil, err
	}
	return Integer(ret), rest, nil
}

func (conn *Connection) readInt() (int64, error) {
	ret, err := conn.readSimpleString()
	if err != nil {
		return -1, err
	}
	parsed, err := strconv.ParseInt(string(ret.(SimpleString)), 10, 64)
	if err != nil {
		return -1, ErrRedisInvalidData
	}
	return parsed, nil
}

func (conn *Connection) readInteger() (RedisValue, error) {
	ret, err := conn.readInt()
	if err != nil {
		return nil, err
	}
	return Integer(ret), nil
}

func decodeErrorMessage(msg []byte) (RedisValue, []byte, error) {
	ret, rest, err := basicRedisDecode('-', msg)
	if err != nil {
		return nil, nil, err
	}
	return ErrorMessage(ret), rest, err
}

func (conn *Connection) readErrorMessage() (RedisValue, error) {
	body, err := conn.readUntilCRLF()
	if err != nil {
		return nil, err
	}
	return ErrorMessage(body), nil
}

func decodeRedisArray(msg []byte) (RedisValue, []byte, error) {
	size, rest, err := intRedisDecode('*', msg)
	if err != nil {
		return nil, nil, err
	}
	ret := make(RedisArray, size)
	for i := 0; int64(i) < size; i++ {
		ret[i], rest, err = DecodeRedisValue(rest)
		if err != nil {
			return nil, nil, err
		}
	}
	return ret, rest, nil
}

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

type redisDataDecoder func([]byte) (RedisValue, []byte, error)
type redisDataReader func(*Connection) (RedisValue, error)

var decoders map[byte]redisDataDecoder

func DecodeRedisValue(msg []byte) (RedisValue, []byte, error) {
	if decoders == nil {
		decoders = map[byte]redisDataDecoder{
			'+': decodeSimpleString,
			':': decodeInteger,
			'-': decodeErrorMessage,
			'$': decodeBulkString,
			'*': decodeRedisArray,
		}
	}
	ch := msg[0]
	decoder, ok := decoders[ch]
	if !ok {
		return nil, nil, ErrRedisInvalidData
	}
	return decoder(msg)
}

var readers map[byte]redisDataReader

// Connection holds the state for a single connection within a scan
type Connection struct {
	scanner *Scanner
	conn    interface {
		io.Reader
		io.Writer
	}
	buffer []byte
}

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

func inlineQuote(arg string) string {
	if strings.ContainsAny(arg, " ") {
		return "\"" + arg + "\""
	}
	return arg
}

func joinMapped(list []string, sep string, mapper func(s string) string) string {
	temp := make([]string, len(list))
	for i, v := range list {
		temp[i] = mapper(v)
	}
	return strings.Join(temp, sep)
}

func getInlineCommand(cmd ...string) string {
	return joinMapped(cmd, " ", inlineQuote)
}

func (conn *Connection) SendInlineCommand(cmd ...string) (RedisValue, error) {
	out := getInlineCommand(cmd...) + "\r\n"
	if err := conn.write([]byte(out)); err != nil {
		return nil, err
	}
	return conn.ReadRedisValue()
}

func (conn *Connection) SendCommands(cmds RedisArray) (RedisValue, error) {
	if err := conn.WriteRedisValue(cmds); err != nil {
		return nil, err
	}
	return conn.ReadRedisValue()
}

func (conn *Connection) SendCommand(cmd ...string) (RedisValue, error) {
	array := make(RedisArray, len(cmd))
	for i, v := range cmd {
		array[i] = BulkString(v)
	}
	return conn.SendCommands(array)
}

func (conn *Connection) WriteRedisValue(value RedisValue) error {
	encoded := value.Encode()
	return conn.write(encoded)
}

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
		return nil, ErrRedisInvalidData
	}
	return reader(conn)
}
