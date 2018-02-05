package redis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var bigBulkString = "--- BEGIN BULK STRING ---\r\nbulk string data\r\n--- END BULK STRING---\r\n"
var bigSimpleString = strings.Repeat("simple,", 1024*1024)

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
	"*1\r\n+\r\n":                             RedisArray{RedisSimpleString("")},
	"*2\r\n*1\r\n*0\r\n*1\r\n$5\r\n12345\r\n": RedisArray{RedisArray{RedisArray{}}, RedisArray{RedisBulkString("12345")}},
	"*5\r\n" +
		"+simpleString\r\n" +
		"-ERR error message\r\n" +
		":12345\r\n" +
		"$47\r\n*5\r\n+simpleString\r\n-ERR error message\r\n:12345\r\n\r\n" +
		"*0\r\n": RedisArray{
		RedisSimpleString("simpleString"),
		RedisError("ERR error message"),
		RedisInteger(12345),
		RedisBulkString([]byte("*5\r\n+simpleString\r\n-ERR error message\r\n:12345\r\n")),
		RedisArray{},
	},
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

func rawDecode(t *testing.T, s string) RedisData {
	ret, rest, err := DecodeRedisData([]byte(s))
	if err != nil {
		t.Errorf("%s cannot be decoded: %v", strip(s), err)
	}
	if len(rest) > 0 {
		t.Errorf("%s has %d bytes left over", strip(s), len(rest))
	}
	return ret
}

func encode(a RedisData) string {
	return string(a.Encode())
}

func decode(t *testing.T, s string) string {
	ret := rawDecode(t, s)
	b, ok := ret.(RedisBulkString)
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
		case RedisBulkString:
			if !bytes.Equal(ait, bi.(RedisBulkString)) {
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
	e0 := RedisSimpleString("foo")
	e1 := RedisBulkString([]byte(bigBulkString))
	e2 := RedisInteger(0)
	e3 := RedisInteger((1 << 62))
	e4 := make(RedisArray, 0)
	e5 := RedisError("ERR some error")
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
		decoded, rest, err := DecodeRedisData([]byte(expectedEncoding))
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

func TestRedisSimpleString(t *testing.T) {
	for k, v := range simpleStrings {
		assertEquals(t, encode(RedisSimpleString(k)), v)
		assertEquals(t, decode(t, v), k)
	}
}

func TestRedisInteger(t *testing.T) {
	for k, v := range integers {
		assertEquals(t, encode(RedisInteger(k)), v)
		assertEquals(t, decode(t, v), fmt.Sprintf("%d", k))
	}
}

func TestRedisBulkString(t *testing.T) {
	for k, v := range bulkStrings {
		assertEquals(t, encode(RedisBulkString(k)), v)
		assertEquals(t, decode(t, v), string(k))
	}
	assertEquals(t, encode(RedisNull), "$-1\r\n")
}

func TestIsRedisNull(t *testing.T) {
	if !IsRedisNull(RedisNull) {
		t.Errorf("!IsRedisNull(&global RedisNull)")
	}
	ret, rest, err := DecodeRedisData([]byte("$-1\r\n"))
	if err != nil {
		t.Errorf("Error decoding null value: %v", err)
	}
	if len(rest) > 0 {
		t.Errorf("Got leftover data when decoding null")
	}
	if !IsRedisNull(ret) {
		t.Errorf("Decoded null string did not return null; got %v", ret)
	}
	for str, array := range redisArrays {
		if IsRedisNull(array) {
			t.Errorf("Non-null array '%s' returned IsRedisNull", str)
		}
	}
	for _, enc := range redisErrors {
		err := rawDecode(t, enc)
		if IsRedisNull(err) {
			t.Errorf("Non-null error message '%s' returned IsRedisNull", enc)
		}
	}
	for _, enc := range integers {
		val := rawDecode(t, enc)
		if IsRedisNull(val) {
			t.Errorf("Non-null integer '%s' returned IsRedisNull", enc)
		}
	}
	for _, enc := range bulkStrings {
		val := rawDecode(t, enc)
		if IsRedisNull(val) {
			t.Errorf("Non-null bulk string '%s' returned IsRedisNull", enc)
		}
	}
	for _, enc := range simpleStrings {
		val := rawDecode(t, enc)
		if IsRedisNull(val) {
			t.Errorf("Non-null simple string '%s' returned IsRedisNull", enc)
		}
	}
}

func TestRedisError(t *testing.T) {
	for k, v := range redisErrors {
		assertEquals(t, encode(RedisError(k)), v)
		assertEquals(t, decode(t, v), k)
		assertEquals(t, RedisError(k).ErrorPrefix(), redisErrorPrefixes[k])
		assertEquals(t, RedisError(k).ErrorMessage(), redisErrorMessages[k])
	}
}
