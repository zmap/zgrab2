package redis

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type RedisType string

const (
	RedisTypeSimpleString RedisType = "simple string"
	RedisTypeError                  = "error"
	RedisTypeInteger                = "integer"
	RedisTypeBulkString             = "bulk string"
	RedisTypeArray                  = "array"
)

type RedisData interface {
	Type() RedisType
	Encode() []byte
}

// Must not contain \r or \n. https://redis.io/topics/protocol#resp-simple-strings
type RedisSimpleString string

func (RedisSimpleString) Type() RedisType {
	return RedisTypeSimpleString
}

func (str RedisSimpleString) Encode() []byte {
	return []byte("+" + str + "\r\n")
}

// https://redis.io/topics/protocol#resp-errors
type RedisError string

func (RedisError) Type() RedisType {
	return RedisTypeError
}

func (err RedisError) Encode() []byte {
	return []byte("-" + err + "\r\n")
}

func (err RedisError) ErrorPrefix() string {
	return strings.SplitN(string(err), " ", 2)[0]
}

func (err RedisError) ErrorMessage() string {
	parts := strings.SplitN(string(err), " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return string(err)
}

// "the returned integer is guaranteed to be in the range of a signed 64 bit integer" (https://redis.io/topics/protocol#resp-integers)
type RedisInteger int64

func (RedisInteger) Type() RedisType {
	return RedisTypeInteger
}

func (val RedisInteger) Encode() []byte {
	return []byte(fmt.Sprintf(":%d\r\n", val))
}

type RedisNullType []byte

var RedisNull RedisNullType = nil

func (RedisNullType) Type() RedisType {
	return RedisTypeBulkString
}

func (RedisNullType) Encode() []byte {
	return []byte("$-1\r\n")
}

func IsRedisNull(data RedisData) bool {
    /*
    if data == nil {
        // the pointer might point to nil, but the pointer itself shouldn't be nil
        return false
    }
    */
    _, ok := data.(RedisNullType)
    return ok
}

type RedisBulkString []byte

func (RedisBulkString) Type() RedisType {
	return RedisTypeBulkString
}

func (str RedisBulkString) Encode() []byte {
	prefix := fmt.Sprintf("$%d\r\n", len(str))
	ret := make([]byte, len(prefix)+len(str)+2)
	copy(ret, []byte(prefix))
	copy(ret[len(prefix):], str)
	ret[len(ret)-2] = '\r'
	ret[len(ret)-1] = '\n'
	return ret
}

// https://redis.io/topics/protocol#resp-arrays
type RedisArray []RedisData

func (RedisArray) Type() RedisType {
	return RedisTypeArray
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

func (conn *RedisConnection) read() ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := conn.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (conn *RedisConnection) readUntilCRLF() ([]byte, error) {
	var idx int
	for idx = -1; idx == -1; idx = bytes.Index(conn.buffer, []byte{'\r', '\n'}) {
		ret, err := conn.read()
		if err != nil {
			return nil, err
		}
		conn.buffer = append(conn.buffer, ret...)
	}
	ret := conn.buffer[:idx]
	conn.buffer = conn.buffer[idx+2:]
	return ret, nil
}

func (conn *RedisConnection) readSimpleString() (RedisData, error) {
	body, err := conn.readUntilCRLF()
	if err != nil {
		return nil, err
	}
	return RedisSimpleString(body), nil
}

func (conn *RedisConnection) readInteger() (RedisData, error) {
	ret, err := conn.readSimpleString()
	if err != nil {
		return nil, err
	}
	parsed, err := strconv.ParseInt(string(ret.(RedisSimpleString)), 10, 64)
	if err != nil {
		return nil, ErrRedisInvalidData
	}
	return RedisInteger(parsed), nil

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

func (conn *RedisConnection) readResponse() (RedisData, error) {
	return nil, nil
}

func decodeRedisBulkString(msg []byte) (RedisData, []byte, error) {
	size, rest, err := intRedisDecode('$', msg)
	if err != nil {
		return nil, nil, err
	}
	if size == -1 {
		return RedisNull, rest, nil
	}
	if int64(len(rest)) < size+2 {
		return nil, nil, ErrRedisInvalidData
	}
	if rest[size] != '\r' || rest[size+1] != '\n' {
		return nil, nil, ErrRedisInvalidData
	}
	return RedisBulkString(rest[0:size]), rest[size+2:], nil
}

func (conn *RedisConnection) readBulkString() (RedisData, error) {
	_size, err := conn.readInteger()
	if err != nil {
		return nil, err
	}
	size := _size.(RedisInteger)
	if size == -1 {
		return RedisNull, nil
	}
	if size < 0 || size > 512*1024*1024 {
		return nil, ErrRedisBadLength
	}
	body := make([]byte, uint64(size)+2)
	_, err = io.ReadFull(conn.conn, body)
	if err != nil {
		return nil, err
	}
	if !(body[size] == '\r' && body[size+1] == '\n') {
		return nil, ErrRedisInvalidData
	}
	return RedisBulkString(body[:size]), nil
}

func decodeRedisSimpleString(msg []byte) (RedisData, []byte, error) {
	ret, rest, err := basicRedisDecode('+', msg)
	if err != nil {
		return nil, nil, err
	}
	return RedisSimpleString(ret), rest, err
}

func decodeRedisInteger(msg []byte) (RedisData, []byte, error) {
	ret, rest, err := intRedisDecode(':', msg)
	if err != nil {
		return nil, nil, err
	}
	return RedisInteger(ret), rest, nil
}

func decodeRedisError(msg []byte) (RedisData, []byte, error) {
	ret, rest, err := basicRedisDecode('-', msg)
	if err != nil {
		return nil, nil, err
	}
	return RedisError(ret), rest, err
}

func decodeRedisArray(msg []byte) (RedisData, []byte, error) {
	size, rest, err := intRedisDecode('*', msg)
	if err != nil {
		return nil, nil, err
	}
	ret := make(RedisArray, size)
	for i := 0; int64(i) < size; i++ {
		ret[i], rest, err = DecodeRedisData(rest)
		if err != nil {
			return nil, nil, err
		}
	}
	return ret, rest, nil
}

type redisDataDecoder func([]byte) (RedisData, []byte, error)
type redisDataReader func(*RedisConnection) (RedisData, error)

var decoders map[byte]redisDataDecoder

func DecodeRedisData(msg []byte) (RedisData, []byte, error) {
	if decoders == nil {
		decoders = map[byte]redisDataDecoder{
			'+': decodeRedisSimpleString,
			':': decodeRedisInteger,
			'-': decodeRedisError,
			'$': decodeRedisBulkString,
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

// redis-specific command-line flags.
type RedisFlags struct {
	zgrab2.BaseFlags
	// TODO: Add more protocol-specific flags
	// Protocols that support TLS should include zgrab2.TLSFlags

	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// RedisModule implements the zgrab2.Module interface
type RedisModule struct {
	// TODO: Add any module-global state
}

// RedisScanner implements the zgrab2.Scanner interface
type RedisScanner struct {
	config *RedisFlags
	target *zgrab2.ScanTarget
	// TODO: Add scan state
}

// RedisConnection holds the state for a single connection within a scan
type RedisConnection struct {
	scanner *RedisScanner
	conn    net.Conn
	buffer  []byte
}

func (conn *RedisConnection) sendCommands(cmds RedisArray) (RedisData, error) {
	toSend := cmds.Encode()
	n, err := conn.conn.Write(toSend)
	if err != nil {
		return nil, err
	}
	if n != len(toSend) {
		return nil, &zgrab2.ScanError{
			Status: zgrab2.SCAN_IO_TIMEOUT,
			Err:    errors.New("incomplete send"),
		}
	}
	// FIXME
	return nil, nil
}

func (conn *RedisConnection) sendCommand(cmd string) (RedisData, error) {
	return nil, nil
}

// redis.init() registers the zgrab2 module
func init() {
	var module RedisModule
	// FIXME: Set default port
	_, err := zgrab2.AddCommand("redis", "redis", "Probe for redis", 6379, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (module *RedisModule) NewFlags() interface{} {
	return new(RedisFlags)
}

func (module *RedisModule) NewScanner() zgrab2.Scanner {
	return new(RedisScanner)
}

func (flags *RedisFlags) Validate(args []string) error {
	return nil
}

func (flags *RedisFlags) Help() string {
	return ""
}

func (scanner *RedisScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*RedisFlags)
	scanner.config = f
	return nil
}

func (scanner *RedisScanner) InitPerSender(senderID int) error {
	return nil
}

func (scanner *RedisScanner) GetName() string {
	return scanner.config.Name
}

func (scanner *RedisScanner) GetPort() uint {
	return scanner.config.Port
}

func (scanner *RedisScanner) connect() (*RedisConnection, error) {
	conn, err := scanner.target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return nil, err
	}
	return &RedisConnection{
		scanner: scanner,
		conn:    conn,
	}, nil
}

// RedisScanner.Scan() TODO: describe what is scanned
func (scanner *RedisScanner) Scan(target zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	scanner.target = &target
	conn, err := scanner.connect()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	fmt.Println("conn=", conn.conn)
	return zgrab2.SCAN_UNKNOWN_ERROR, nil, nil
}
