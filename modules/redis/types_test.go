package redis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type fakeIO struct {
	input  chan byte
	output chan byte
}

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

func (fakeio *fakeIO) Write(buf []byte) (int, error) {
	for _, v := range buf {
		fakeio.input <- v
	}
	return len(buf), nil
}

func (fakeio *fakeIO) Push(buf []byte) {
	go func() {
		// push new bytes as the buffer clears
		for _, v := range buf {
			fakeio.output <- v
		}
	}()
}

var bigBulkString = "--- BEGIN BULK STRING ---\r\nbulk string data\r\n--- END BULK STRING---\r\n"
var bigSimpleString = strings.Repeat("simple,", 1024)

var simpleStrings = map[string]string{
	"":                 "+\r\n",
	"foo":              "+foo\r\n",
	"0123456789abcdef": "+0123456789abcdef\r\n",
	bigSimpleString:    "+" + bigSimpleString + "\r\n",
}

var bulkStrings = map[string]string{
	"":                 "$0\r\n\r\n",
	"foo":              "$3\r\nfoo\r\n",
	"0123456789abcdef": "$16\r\n0123456789abcdef\r\n",
	bigBulkString:      fmt.Sprintf("$%d\r\n%s\r\n", len(bigBulkString), bigBulkString),
}

var integers = map[int64]string{
	0:             ":0\r\n",
	1:             ":1\r\n",
	-1:            ":-1\r\n",
	(1 << 63) - 1: ":9223372036854775807\r\n",
	-(1 << 63):    ":-9223372036854775808\r\n",
	12345:         ":12345\r\n",
}

var redisErrors = map[string]string{
	"": "-\r\n",
	"ERR something went wrong": "-ERR something went wrong\r\n",
	"singleword":               "-singleword\r\n",
}

var redisErrorPrefixes = map[string]string{
	"": "",
	"ERR something went wrong": "ERR",
	"singleword":               "singleword",
}

var redisErrorMessages = map[string]string{
	"": "",
	"ERR something went wrong": "something went wrong",
	"singleword":               "singleword",
}

// Note: reverse key/value order from other maps
var redisArrays = map[string]RedisArray{
	"*0\r\n":                                  RedisArray{},
	"*1\r\n+\r\n":                             RedisArray{SimpleString("")},
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

func getConnection() (*Connection, *fakeIO) {
	fakeIO := fakeIO{
		output: make(chan byte, 1024),
		input:  make(chan byte, 1024),
	}
	conn := Connection{conn: &fakeIO}
	return &conn, &fakeIO
}

func strip(s interface{}) string {
	v := fmt.Sprintf("%v", s)
	if len(v) > 32 {
		return v[0:20] + "..." + v[len(v)-10:]
	}
	return v
}

func stripAround(s []byte, i int) []byte {
	lower := i - 3
	if lower < 0 {
		lower = 0
	}
	upper := i + 3
	if upper >= len(s) {
		upper = len(s) - 1
	}
	if upper < lower {
		upper = lower
	}
	return s[lower:upper]
}

func assertEquals(t *testing.T, actual interface{}, expected interface{}) {
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatalf("Error JSON-encoding %v: %v", actual, err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatalf("Error JSON-encoding %v: %v", expected, err)
	}
	mid := ""
	if string(actualJSON) != string(expectedJSON) {
		for i := 0; i < len(expectedJSON); i++ {
			ai := expectedJSON[i]
			bi := byte(0)
			if i < len(actualJSON) {
				bi = actualJSON[i]
			}
			if ai != bi {
				mid = mid + fmt.Sprintf("[%d: '%s' != '%s']", i, string(stripAround(expectedJSON, i)), string(stripAround(actualJSON, i)))
			}
		}
		t.Errorf("Expected [<%s>], got [<%s>]: %s", strip(string(expectedJSON)), strip(string(actualJSON)), mid)
	}
}

func rawRead(t *testing.T, conn *Connection) RedisValue {
	ret, err := conn.ReadRedisValue()
	if err != nil {
		t.Errorf("Error reading value: %v", err)
	}
	return ret
}

func rawDecode(t *testing.T, s string) RedisValue {
	ret, rest, err := DecodeRedisValue([]byte(s))
	if err != nil {
		t.Errorf("%s cannot be decoded: %v", strip(s), err)
	}
	if len(rest) > 0 {
		t.Errorf("%s has %d bytes left over", strip(s), len(rest))
	}
	return ret
}

func read(t *testing.T, conn *Connection) string {
	ret := rawRead(t, conn)
	b, ok := ret.(BulkString)
	if ok {
		return string(b)
	}
	return fmt.Sprintf("%v", ret)
}

func encode(a RedisValue) string {
	return string(a.Encode())
}

func decode(t *testing.T, s string) string {
	ret := rawDecode(t, s)
	b, ok := ret.(BulkString)
	if ok {
		return string(b)
	}
	return fmt.Sprintf("%v", ret)
}

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

func compareArrays(a, b RedisArray) error {
	return _compareArrays(a, b, "")
}

func TestRedisArray(t *testing.T) {
	var array RedisArray
	e0 := SimpleString("foo")
	e1 := BulkString([]byte(bigBulkString))
	e2 := Integer(0)
	e3 := Integer((1 << 62))
	e4 := make(RedisArray, 0)
	e5 := ErrorMessage("ERR some error")
	assertEquals(t, encode(array), "*0\r\n")
	array = append(array, e0)
	assertEquals(t, encode(array), "*1\r\n"+encode(e0))
	array = append(array, e1)
	assertEquals(t, encode(array), "*2\r\n"+encode(e0)+encode(e1))
	array = append(array, e2)
	assertEquals(t, encode(array), "*3\r\n"+encode(e0)+encode(e1)+encode(e2))
	array = append(array, e3)
	assertEquals(t, encode(array), "*4\r\n"+encode(e0)+encode(e1)+encode(e2)+encode(e3))
	array = append(array, e4)
	assertEquals(t, encode(array), "*5\r\n"+encode(e0)+encode(e1)+encode(e2)+encode(e3)+encode(e4))
	array = append(array, e5)
	assertEquals(t, encode(array), "*6\r\n"+encode(e0)+encode(e1)+encode(e2)+encode(e3)+encode(e4)+encode(e5))

	for expectedEncoding, redisData := range redisArrays {
		assertEquals(t, encode(redisData), expectedEncoding)
		decoded, rest, err := DecodeRedisValue([]byte(expectedEncoding))
		if err != nil {
			t.Errorf("%s cannot be decoded: %v", strip(expectedEncoding), err)
		}
		if len(rest) > 0 {
			t.Errorf("%s has %d bytes left over", strip(expectedEncoding), len(rest))
		}

		if err := compareArrays(decoded.(RedisArray), redisData); err != nil {
			t.Errorf("Decode error: %v", err)
		}
	}
}

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

func readWrite(t *testing.T, conn *Connection, io *fakeIO, value RedisValue) {
	encoded := value.Encode()
	io.Push(encoded)
	decoded, err := conn.ReadRedisValue()
	if err != nil {
		t.Fatalf("Error decoding value for %s: %v", strip(string(encoded)), err)
	}
	if err = compareRedisValues(decoded, value); err != nil {
		t.Errorf("Read value did not match original value: %s != %s: %v", strip(decoded), strip(value), err)
	}
}

func TestSimpleString(t *testing.T) {
	conn, io := getConnection()
	for k, v := range simpleStrings {
		assertEquals(t, encode(SimpleString(k)), v)
		assertEquals(t, decode(t, v), k)
		readWrite(t, conn, io, SimpleString(k))
	}
}

func TestInteger(t *testing.T) {
	conn, io := getConnection()
	for k, v := range integers {
		assertEquals(t, encode(Integer(k)), v)
		assertEquals(t, decode(t, v), fmt.Sprintf("%d", k))
		readWrite(t, conn, io, Integer(k))
	}
}

func TestBulkString(t *testing.T) {
	conn, io := getConnection()
	for k, v := range bulkStrings {
		assertEquals(t, encode(BulkString(k)), v)
		assertEquals(t, decode(t, v), string(k))
		readWrite(t, conn, io, BulkString(k))
	}
	assertEquals(t, encode(NullValue), "$-1\r\n")
	readWrite(t, conn, io, NullValue)
}

func TestIsNullValue(t *testing.T) {
	if !IsNullValue(NullValue) {
		t.Errorf("!IsNullValue(&global RedisNull)")
	}
	ret, rest, err := DecodeRedisValue([]byte("$-1\r\n"))
	if err != nil {
		t.Errorf("Error decoding null value: %v", err)
	}
	if len(rest) > 0 {
		t.Errorf("Got leftover data when decoding null")
	}
	if !IsNullValue(ret) {
		t.Errorf("Decoded null string did not return null; got %v", ret)
	}
	for str, array := range redisArrays {
		if IsNullValue(array) {
			t.Errorf("Non-null array '%s' returned IsNullValue", str)
		}
	}
	for _, enc := range redisErrors {
		err := rawDecode(t, enc)
		if IsNullValue(err) {
			t.Errorf("Non-null error message '%s' returned IsNullValue", enc)
		}
	}
	for _, enc := range integers {
		val := rawDecode(t, enc)
		if IsNullValue(val) {
			t.Errorf("Non-null integer '%s' returned IsNullValue", enc)
		}
	}
	for _, enc := range bulkStrings {
		val := rawDecode(t, enc)
		if IsNullValue(val) {
			t.Errorf("Non-null bulk string '%s' returned IsNullValue", enc)
		}
	}
	for _, enc := range simpleStrings {
		val := rawDecode(t, enc)
		if IsNullValue(val) {
			t.Errorf("Non-null simple string '%s' returned IsNullValue", enc)
		}
	}
}

func TestErrorMessage(t *testing.T) {
	conn, io := getConnection()
	for k, v := range redisErrors {
		assertEquals(t, encode(ErrorMessage(k)), v)
		assertEquals(t, decode(t, v), k)
		assertEquals(t, ErrorMessage(k).ErrorPrefix(), redisErrorPrefixes[k])
		assertEquals(t, ErrorMessage(k).ErrorMessage(), redisErrorMessages[k])
		readWrite(t, conn, io, ErrorMessage(k))
	}
}
