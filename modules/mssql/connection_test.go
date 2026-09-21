package mssql

import (
	"errors"
	"testing"
)

// TestDecodePreloginOptionsOverflow ensures a PRELOGIN option whose
// offset+length overflows a uint16 is rejected as invalid data rather than
// panicking with an out-of-range slice. A malicious MSSQL server controls
// these fields, so the bounds check must not be defeated by integer overflow.
func TestDecodePreloginOptionsOverflow(t *testing.T) {
	// token=0x00, offset=0xFFFF, length=0x0002 (offset+length wraps to 1 in
	// uint16 arithmetic), terminator=0xff.
	body := []byte{0x00, 0xFF, 0xFF, 0x00, 0x02, 0xFF}
	opts, rest, err := decodePreloginOptions(body)
	if !errors.Is(err, ErrInvalidData) {
		t.Fatalf("expected ErrInvalidData, got opts=%v rest=%v err=%v", opts, rest, err)
	}
}

// TestDecodePreloginOptionsValid confirms a well-formed PRELOGIN body still
// decodes correctly after the overflow-hardening change.
func TestDecodePreloginOptionsValid(t *testing.T) {
	// One option: token=0x00, offset=0x0006 (points just past the 6-byte
	// header: 5-byte option entry + 0xff terminator), length=0x0002; followed
	// by the terminator and the 2 value bytes.
	body := []byte{0x00, 0x00, 0x06, 0x00, 0x02, 0xFF, 0xAB, 0xCD}
	opts, _, err := decodePreloginOptions(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, ok := (*opts)[PreloginOptionToken(0x00)]
	if !ok {
		t.Fatalf("expected token 0x00 to be present, got %v", *opts)
	}
	if want := []byte{0xAB, 0xCD}; string(got) != string(want) {
		t.Fatalf("expected value %v, got %v", want, got)
	}
}
