package ipp

import (
	"bytes"
	"encoding/binary"
	//"io"
	"net"
)

type Connection struct {
	Conn net.Conn
}

//func ReadResponse(body *io.ReadCloser) *ScanResults {
//	result := &ScanResults{}
//
//}

// Returns a byte-encoded "attribute-with-one-value" with the provided "value-tag", "name", and "value"
// attribute-with-one-value encoding described at https://tools.ietf.org/html/rfc8010#section-3.1.4
// Example (runnable from ipp_test.go):
//   Input: 0x47, "attributes-charset", "us-ascii"
//   Output: [71 0 18 97 116 116 114 105 98 117 116 101 115 45 99 104 97 114 115 101 116 0 8 117 115 45 97 115 99 105 105]
// TODO: Should return an error when fed an invalid valueTag?
// TODO: Determine whether this should remain public. Currently is for Testable Example
func AttributeByteString(valueTag byte, name string, value string) []byte {
	//special byte denoting value syntax
	b := []byte{valueTag}

	//append 16-bit signed int denoting name length
	l := new(bytes.Buffer)
	binary.Write(l, binary.BigEndian, int16(len(name)))
	b = append(b, l.Bytes()...)

	//append name
	b = append(b, []byte(name)...)

	//append 16-bit signed int denoting value length
	l = new(bytes.Buffer)
	binary.Write(l, binary.BigEndian, int16(len(value)))
	b = append(b, l.Bytes()...)

	//append value
	b = append(b, []byte(value)...)
	return b
}


// IPP request encoding described at https://tools.ietf.org/html/rfc8010#section-3.1.1
//TODO: Store everything except uri statically?
//Construct a minimal request that an IPP server will respond to
func getPrinterAttributesRequest(uri string) bytes.Buffer {
	var b bytes.Buffer
	//version 2.1 (newest as of 2018)
	b.Write([]byte{2, 1})
	//operation-id = get-printer-attributes
	b.Write([]byte{0, 0xb})
	//request-id = 1
	b.Write([]byte{0, 0, 0, 1})
	//operation-attributes-tag = 1 (begins an attribute-group)
	b.Write([]byte{1})

	//attributes-charset
	b.Write(AttributeByteString(0x47, "attributes-charset", "utf-8"))
	//attributes-natural-language
	b.Write(AttributeByteString(0x48, "attributes-natural-language", "en-us"))
	//printer-uri
	b.Write(AttributeByteString(0x45, "printer-uri", uri))
	//requested-attributes
	b.Write(AttributeByteString(0x44, "requested-attributes", "all"))

	//end-of-attributes-tag = 3
	b.Write([]byte{3})

	return b
}