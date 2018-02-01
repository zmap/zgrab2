package modules

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type redisConnection struct {
	conn net.Conn
	scan *redisScanner
}

type redisType string

const (
	redisTypeSimpleString redisType = "simple string"
	redisTypeError = "error"
	redisTypeInteger = "integer"
	redisTypeBulkString = "bulk string"
	redisTypeArray = "array"
)

type redisData interface {
	Type() redisType
	Encode() []byte
}

// Must not contain \r or \n. https://redis.io/topics/protocol#resp-simple-strings
type redisSimpleString string

func (self redisSimpleString) Type() redisType {
	return redisTypeSimpleString
}

func (self redisSimpleString) Encode() []byte {
	return []byte("+" + self + "\r\n")
}

// https://redis.io/topics/protocol#resp-errors
type redisError string

func (self redisError) Type() redisType {
	return redisTypeError
}

func (self redisError) Encode() []byte {
	return []byte("-" + self + "\r\n")
}

func (self redisError) ErrorPrefix() string {
	return strings.SplitN(string(self), " ", 2)[0]
}

func (self redisError) ErrorMessage() string {
	parts := strings.SplitN(string(self), " ", 2)
	if len(parts) == 2 {
		return parts[1]
	} else {
		return string(self)
	}
}

// "the returned integer is guaranteed to be in the range of a signed 64 bit integer" (https://redis.io/topics/protocol#resp-integers)
type redisInteger int64

func (self redisInteger) Type() redisType {
	return redisTypeInteger
}

func (self redisInteger) Encode() []byte {
	return []byte(fmt.Sprintf(":%d\r\n", self))
}

type redisNullBulkStringType string

const redisNullBulkString redisNullBulkStringType = "<NULL>"

func (self redisNullBulkStringType) Type() redisType {
	return redisTypeBulkString
}

func (self redisNullBulkStringType) Encode() []byte {
	return []byte("$-1\r\n")
}

type redisBulkString []byte

func (self redisBulkString) Type() redisType {
	return redisTypeBulkString
}

func (self redisBulkString) Encode() []byte {
	prefix := fmt.Sprintf("$%d\r\n", len(self))
	ret := make([]byte, len(prefix) + len(self) + 2)
	copy(ret, []byte(prefix))
	copy(ret[len(prefix):], self)
	ret[len(ret) - 2] = '\r'
	ret[len(ret) - 1] = '\n'
	return ret
}

// https://redis.io/topics/protocol#resp-arrays
type redisArray []redisData

func (self redisArray) Type() redisType {
	return redisTypeArray
}

func (self redisArray) Encode() []byte {
	var ret []byte
	prefix := fmt.Sprintf("*%d\r\n", len(self))
	ret = append(ret, []byte(prefix)...)
	for _, item := range self {
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
	redisErrInvalidData error = fmt.Errorf("Invalid data")
	redisErrWrongType = fmt.Errorf("Wrong type specifier")
)

func basicRedisDecode(id byte, msg []byte) (string, []byte, error) {
	if msg[0] != id {
		return "", nil, redisErrWrongType
	}
	str := string(msg)
	idx := strings.Index(str, "\r\n")
	if idx == -1 {
		return "", nil, redisErrInvalidData
	}
	return string(msg[1:idx]), msg[idx + 2:], nil
}

func intRedisDecode(id byte, msg[]byte) (int64, []byte, error) {
	ret, rest, err := basicRedisDecode(id, msg)
	if err != nil {
		return 0, nil, err
	}
	parsed, err := strconv.ParseInt(ret, 10, 64)
	if err != nil {
		return 0, nil, redisErrInvalidData
	}
	return parsed, rest, nil
}

func decodeRedisBulkString(msg []byte) (redisData, []byte, error) {
	size, rest, err := intRedisDecode('$', msg)
	if err != nil {
		return nil, nil, err
	}
	if size == -1 {
		return redisNullBulkString, rest, nil
	}
	if int64(len(rest)) < size + 2 {
		return nil, nil, redisErrInvalidData
	}
	if rest[size] != '\r' || rest[size + 1] != '\n' {
		return nil, nil, redisErrInvalidData
	}
	return redisBulkString(rest[0:size]), rest[size + 2:], nil
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
	for i := 0; i < size; i++ {
		ret[i], rest, err := decodeRedisData(rest)
		if err != nil {
			return nil, nil, err
		}
	}
	return ret, rest, nil
}

type redisDataDecoder func([]byte) (redisData, []byte, error)

var decoders map[byte]redisDataDecoder = map[byte]redisDataDecoder{
	'+': decodeRedisSimpleString,
	':': decodeRedisInteger,
	'-': decodeRedisError,
	'$': decodeRedisBulkString,
	'*': decodeRedisArray,
}

func decodeRedisData(msg []byte) (redisData, []byte, error) {
	ch := msg[0]
	decoder, ok := decoders[ch]
	if !ok {
		return nil, nil, redisErrInvalidData
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
	// TODO: Add scan state
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

func (m *redisModule) NewFlags() interface{} {
	return new(redisFlags)
}

func (m *redisModule) NewScanner() zgrab2.Scanner {
	return new(redisScanner)
}

func (f *redisFlags) Validate(args []string) error {
	return nil
}

func (f *redisFlags) Help() string {
	return ""
}

func (s *redisScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*redisFlags)
	s.config = f
	return nil
}

func (s *redisScanner) InitPerSender(senderID int) error {
	return nil
}

func (s *redisScanner) GetName() string {
	return s.config.Name
}

func (s *redisScanner) GetPort() uint {
	return s.config.Port
}

// redisScanner.Scan() TODO: describe what is scanned
func (s *redisScanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	// TODO: implement
	return zgrab2.SCAN_UNKNOWN_ERROR, nil, nil
}
