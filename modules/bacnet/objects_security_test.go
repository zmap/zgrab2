package bacnet

import (
	"encoding/binary"
	"testing"
)

// --- readInstanceNumber tests ---

func buildInstanceNumber(open, app byte, instanceNum uint32, close byte) []byte {
	buf := []byte{open, app}
	numBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(numBytes, instanceNum)
	buf = append(buf, numBytes...)
	buf = append(buf, close)
	return buf
}

func TestReadInstanceNumber_Valid(t *testing.T) {
	b := buildInstanceNumber(0x3e, 0xc4, 0x00010042, 0x3f)
	leftovers, instanceNumber, err := readInstanceNumber(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := uint32(0x00010042) & 0x0003ffff
	if instanceNumber != expected {
		t.Errorf("expected instance %d, got %d", expected, instanceNumber)
	}
	if len(leftovers) != 0 {
		t.Errorf("expected no leftovers, got %d bytes", len(leftovers))
	}
}

func TestReadInstanceNumber_BadOpenTag(t *testing.T) {
	b := buildInstanceNumber(0x99, 0xc4, 42, 0x3f)
	_, _, err := readInstanceNumber(b)
	if err == nil {
		t.Fatal("expected error for bad open tag, got nil")
	}
}

func TestReadInstanceNumber_BadAppTag(t *testing.T) {
	b := buildInstanceNumber(0x3e, 0x99, 42, 0x3f)
	_, _, err := readInstanceNumber(b)
	if err == nil {
		t.Fatal("expected error for bad app tag, got nil")
	}
}

func TestReadInstanceNumber_BadCloseTag(t *testing.T) {
	b := buildInstanceNumber(0x3e, 0xc4, 42, 0x99)
	_, _, err := readInstanceNumber(b)
	if err == nil {
		t.Fatal("expected error for bad close tag, got nil")
	}
}

func TestReadInstanceNumber_Empty(t *testing.T) {
	_, _, err := readInstanceNumber([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

func TestReadInstanceNumber_TruncatedAfterApp(t *testing.T) {
	// open + app but no instance number bytes
	_, _, err := readInstanceNumber([]byte{0x3e, 0xc4})
	if err == nil {
		t.Fatal("expected error for truncated input, got nil")
	}
}

// --- readVendorID tests ---

func TestReadVendorID_Valid16Bit(t *testing.T) {
	buf := []byte{0x3e, 0x22}
	vendorBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(vendorBytes, 0x1234)
	buf = append(buf, vendorBytes...)
	buf = append(buf, 0x3f)

	_, vendorID, err := readVendorID(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vendorID != 0x1234 {
		t.Errorf("expected vendor 0x1234, got 0x%04x", vendorID)
	}
}

func TestReadVendorID_Valid8Bit(t *testing.T) {
	buf := []byte{0x3e, 0x21, 0x42, 0x3f}
	_, vendorID, err := readVendorID(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vendorID != 0x42 {
		t.Errorf("expected vendor 0x42, got 0x%04x", vendorID)
	}
}

func TestReadVendorID_BadOpenTag(t *testing.T) {
	buf := []byte{0x99, 0x22, 0x00, 0x01, 0x3f}
	_, _, err := readVendorID(buf)
	if err == nil {
		t.Fatal("expected error for bad open tag, got nil")
	}
}

func TestReadVendorID_BadAppTag(t *testing.T) {
	buf := []byte{0x3e, 0x99, 0x00, 0x01, 0x3f}
	_, _, err := readVendorID(buf)
	if err == nil {
		t.Fatal("expected error for bad app tag, got nil")
	}
}

func TestReadVendorID_BadCloseTag(t *testing.T) {
	buf := []byte{0x3e, 0x21, 0x42, 0x99}
	_, _, err := readVendorID(buf)
	if err == nil {
		t.Fatal("expected error for bad close tag, got nil")
	}
}

func TestReadVendorID_Empty(t *testing.T) {
	_, _, err := readVendorID([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

// --- readStringProperty tests ---

func buildStringProperty(open, appByte byte, content []byte, close byte) []byte {
	buf := []byte{open, appByte}
	buf = append(buf, content...)
	buf = append(buf, close)
	return buf
}

func TestReadStringProperty_Valid(t *testing.T) {
	// appByte 0x74 = 0x70 | 0x04 (length=4), content = encoding(1) + "abc"(3)
	content := []byte{0x00, 'a', 'b', 'c'}
	b := buildStringProperty(0x3e, 0x74, content, 0x3f)
	_, value, err := readStringProperty(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "abc" {
		t.Errorf("expected 'abc', got %q", value)
	}
}

func TestReadStringProperty_BadOpenTag(t *testing.T) {
	content := []byte{0x00, 'x'}
	b := buildStringProperty(0x99, 0x72, content, 0x3f)
	_, _, err := readStringProperty(b)
	if err == nil {
		t.Fatal("expected error for bad open tag, got nil")
	}
}

func TestReadStringProperty_BadAppTag(t *testing.T) {
	content := []byte{0x00, 'x'}
	b := buildStringProperty(0x3e, 0x50, content, 0x3f)
	_, _, err := readStringProperty(b)
	if err == nil {
		t.Fatal("expected error for bad app tag, got nil")
	}
}

func TestReadStringProperty_BadCloseTag(t *testing.T) {
	content := []byte{0x00, 'a', 'b', 'c'}
	b := buildStringProperty(0x3e, 0x74, content, 0x99)
	_, _, err := readStringProperty(b)
	if err == nil {
		t.Fatal("expected error for bad close tag, got nil")
	}
}

func TestReadStringProperty_Empty(t *testing.T) {
	_, _, err := readStringProperty([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}
