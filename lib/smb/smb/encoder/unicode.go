package encoder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

func FromUnicode(d []byte) (string, error) {
	// Credit to https://github.com/Azure/go-ntlmssp/blob/master/unicode.go for logic
	if len(d)%2 > 0 {
		return "", errors.New("unicode (UTF 16 LE) specified, but uneven data length")
	}
	s := make([]uint16, len(d)/2)
	err := binary.Read(bytes.NewReader(d), binary.LittleEndian, &s)
	if err != nil {
		return "", err
	}
	return string(utf16.Decode(s)), nil
}

func ToUnicode(s string) []byte {
	// Credit to https://github.com/Azure/go-ntlmssp/blob/master/unicode.go for logic
	uints := utf16.Encode([]rune(s))
	b := bytes.Buffer{}
	binary.Write(&b, binary.LittleEndian, &uints)
	return b.Bytes()
}

func ToSmbString(s string) []byte {
	res := ToUnicode(s)
	res = append(res, 0x0, 0x0)
	return res
}

func FromSmbString(d []byte) (string, error) {
	res, err := FromUnicode(d)
	if err != nil {
		return "", err
	}
	if len(res) == 0 {
		return "", nil
	}
	// Trim null terminator
	return res[:len(res)-1], nil
}
