package modules

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

type redisType string

const (
	redisTypeSimpleString redisType = "simple string"
	redisTypeError                  = "error"
	redisTypeInteger                = "integer"
	redisTypeBulkString             = "bulk string"
	redisTypeArray                  = "array"
)

type redisData interface {
	Type() redisType
	Encode() []byte
}

// Must not contain \r or \n. https://redis.io/topics/protocol#resp-simple-strings
type redisSimpleString string

func (redisSimpleString) Type() redisType {
	return redisTypeSimpleString
}

func (str redisSimpleString) Encode() []byte {
	return []byte("+" + str + "\r\n")
}

// https://redis.io/topics/protocol#resp-errors
type redisError string

func (redisError) Type() redisType {
	return redisTypeError
}

func (err redisError) Encode() []byte {
	return []byte("-" + err + "\r\n")
}

func (err redisError) ErrorPrefix() string {
	return strings.SplitN(string(err), " ", 2)[0]
}

func (err redisError) ErrorMessage() string {
	parts := strings.SplitN(string(err), " ", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return string(err)
}

// "the returned integer is guaranteed to be in the range of a signed 64 bit integer" (https://redis.io/topics/protocol#resp-integers)
type redisInteger int64

func (redisInteger) Type() redisType {
	return redisTypeInteger
}

func (val redisInteger) Encode() []byte {
	return []byte(fmt.Sprintf(":%d\r\n", val))
}

type redisNullType []byte

var redisNull redisNullType = nil

func (redisNullType) Type() redisType {
	return redisTypeBulkString
}

func (redisNullType) Encode() []byte {
	return []byte("$-1\r\n")
}

type redisBulkString []byte

func (redisBulkString) Type() redisType {
	return redisTypeBulkString
}

func (str redisBulkString) Encode() []byte {
	prefix := fmt.Sprintf("$%d\r\n", len(str))
	ret := make([]byte, len(prefix)+len(str)+2)
	copy(ret, []byte(prefix))
	copy(ret[len(prefix):], str)
	ret[len(ret)-2] = '\r'
	ret[len(ret)-1] = '\n'
	return ret
}

// https://redis.io/topics/protocol#resp-arrays
type redisArray []redisData

func (redisArray) Type() redisType {
	return redisTypeArray
}

func (array redisArray) Encode() []byte {
	var ret []byte
	prefix := fmt.Sprintf("*%d\r\n", len(array))
	ret = append(ret, []byte(prefix)...)
	for _, item := range array {
		ret = append(ret, item.Encode()...)
	}
	return ret
}

// redisScanResults is the output of the scan.
type redisScanResults struct {
	infoResponse string
	// TODO: Add protocol

	// Protocols that support TLS should include
	// TLSLog      *zgrab2.TLSLog `json:"tls,omitempty"`
}

var (
	errRedisInvalidData = errors.New("invalid data")
	errRedisWrongType   = errors.New("wrong type specifier")
	errRedisBadLength   = errors.New("bad length")
)

func (conn *redisConnection) read() ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := conn.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (conn *redisConnection) readUntilCRLF() ([]byte, error) {
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

func (conn *redisConnection) readSimpleString() (redisData, error) {
	body, err := conn.readUntilCRLF()
	if err != nil {
		return nil, err
	}
	return redisSimpleString(body), nil
}

func (conn *redisConnection) readInteger() (redisData, error) {
	ret, err := conn.readSimpleString()
	if err != nil {
		return nil, err
	}
	parsed, err := strconv.ParseInt(string(ret.(redisSimpleString)), 10, 64)
	if err != nil {
		return nil, errRedisInvalidData
	}
	return redisInteger(parsed), nil

}

func basicRedisDecode(id byte, msg []byte) (string, []byte, error) {
	if msg[0] != id {
		return "", nil, errRedisWrongType
	}
	str := string(msg)
	idx := strings.Index(str, "\r\n")
	if idx == -1 {
		return "", nil, errRedisInvalidData
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
		return 0, nil, errRedisInvalidData
	}
	return parsed, rest, nil
}

func (conn *redisConnection) readResponse() (redisData, error) {
	return nil, nil
}

func decodeRedisBulkString(msg []byte) (redisData, []byte, error) {
	size, rest, err := intRedisDecode('$', msg)
	if err != nil {
		return nil, nil, err
	}
	if size == -1 {
		return redisNull, rest, nil
	}
	if int64(len(rest)) < size+2 {
		return nil, nil, errRedisInvalidData
	}
	if rest[size] != '\r' || rest[size+1] != '\n' {
		return nil, nil, errRedisInvalidData
	}
	return redisBulkString(rest[0:size]), rest[size+2:], nil
}

func (conn *redisConnection) readBulkString() (redisData, error) {
	_size, err := conn.readInteger()
	if err != nil {
		return nil, err
	}
	size := _size.(redisInteger)
	if size == -1 {
		return redisNull, nil
	}
	if size < 0 || size > 512*1024*1024 {
		return nil, errRedisBadLength
	}
	body := make([]byte, uint64(size)+2)
	_, err = io.ReadFull(conn.conn, body)
	if err != nil {
		return nil, err
	}
	if !(body[size] == '\r' && body[size+1] == '\n') {
		return nil, errRedisInvalidData
	}
	return redisBulkString(body[:size]), nil
}

func decodeRedisSimpleString(msg []byte) (redisData, []byte, error) {
	ret, rest, err := basicRedisDecode('+', msg)
	if err != nil {
		return nil, nil, err
	}
	return redisSimpleString(ret), rest, err
}

func decodeRedisInteger(msg []byte) (redisData, []byte, error) {
	ret, rest, err := intRedisDecode(':', msg)
	if err != nil {
		return nil, nil, err
	}
	return redisInteger(ret), rest, nil
}

func decodeRedisError(msg []byte) (redisData, []byte, error) {
	ret, rest, err := basicRedisDecode('-', msg)
	if err != nil {
		return nil, nil, err
	}
	return redisError(ret), rest, err
}

func decodeRedisArray(msg []byte) (redisData, []byte, error) {
	size, rest, err := intRedisDecode('*', msg)
	if err != nil {
		return nil, nil, err
	}
	ret := make(redisArray, size)
	for i := 0; int64(i) < size; i++ {
		ret[i], rest, err = decodeRedisData(rest)
		if err != nil {
			return nil, nil, err
		}
	}
	return ret, rest, nil
}

type redisDataDecoder func([]byte) (redisData, []byte, error)
type redisDataReader func(*redisConnection) (redisData, error)

var decoders map[byte]redisDataDecoder

func decodeRedisData(msg []byte) (redisData, []byte, error) {
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
		return nil, nil, errRedisInvalidData
	}
	return decoder(msg)
}

// redis-specific command-line flags.
type redisFlags struct {
	zgrab2.BaseFlags
	// TODO: Add more protocol-specific flags
	// Protocols that support TLS should include zgrab2.TLSFlags

	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// redisModule implements the zgrab2.Module interface
type redisModule struct {
	// TODO: Add any module-global state
}

// redisScanner implements the zgrab2.Scanner interface
type redisScanner struct {
	config *redisFlags
	target *zgrab2.ScanTarget
	// TODO: Add scan state
}

// redisConnection holds the state for a single connection within a scan
type redisConnection struct {
	scanner *redisScanner
	conn    net.Conn
	buffer  []byte
}

func (conn *redisConnection) sendCommands(cmds redisArray) (redisData, error) {
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

func (conn *redisConnection) sendCommand(cmd string) (redisData, error) {
	return nil, nil
}

// redis.init() registers the zgrab2 module
func init() {
	var module redisModule
	// FIXME: Set default port
	_, err := zgrab2.AddCommand("redis", "redis", "Probe for redis", 6379, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (module *redisModule) NewFlags() interface{} {
	return new(redisFlags)
}

func (module *redisModule) NewScanner() zgrab2.Scanner {
	return new(redisScanner)
}

func (flags *redisFlags) Validate(args []string) error {
	return nil
}

func (flags *redisFlags) Help() string {
	return ""
}

func (scanner *redisScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*redisFlags)
	scanner.config = f
	return nil
}

func (scanner *redisScanner) InitPerSender(senderID int) error {
	return nil
}

func (scanner *redisScanner) GetName() string {
	return scanner.config.Name
}

func (scanner *redisScanner) GetPort() uint {
	return scanner.config.Port
}

func (scanner *redisScanner) connect() (*redisConnection, error) {
	conn, err := scanner.target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return nil, err
	}
	return &redisConnection{
		scanner: scanner,
		conn:    conn,
	}, nil
}

// redisScanner.Scan() TODO: describe what is scanned
func (scanner *redisScanner) Scan(target zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	scanner.target = &target
	conn, err := scanner.connect()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	fmt.Println("conn=", conn.conn)
	return zgrab2.SCAN_UNKNOWN_ERROR, nil, nil
}
