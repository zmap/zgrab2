package ipp

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// Returns a byte-encoded "attribute-with-one-value" with the provided "value-tag", "name", and "value"
// attribute-with-one-value encoding described at https://tools.ietf.org/html/rfc8010#section-3.1.4
// TODO: Change example to read out in hex
// Example (runnable from ipp_test.go):
//   Input: 0x47, "attributes-charset", "us-ascii"
//   Output: [71 0 18 97 116 116 114 105 98 117 116 101 115 45 99 104 97 114 115 101 116 0 8 117 115 45 97 115 99 105 105]
// TODO: Should return an error when fed an invalid valueTag?
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

func convertURIToIPP(uri string) string {
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		uri = strings.Replace(uri, "http", "ipp", 1)
	}
	// FIXME: Or assume that port is already specified
	// TODO: Ensure that port is explicitly specified, otherwise specify 631
	// TODO: Outlaw literal IP addresses in v4 or v6
	sections := strings.Split(uri, "/")
	if !strings.Contains(sections[2], ":") {
		sections[2] += ":631"
	}
	// TODO: Make sure that this properly constructs a valid uri
	if strings.HasPrefix(uri, "ipp://") {
		return uri
	}
	// FIXME: This is a bodge
	return "ipp://" + uri
}

func getDevicesRequest() *bytes.Buffer {
	var b bytes.Buffer
	//version = 3.0 newer than anything extant
	b.Write([]byte{2, 1})
	//operation-id = get-printer-attributes
	b.Write([]byte{0x40, 0x0b})
	//request-id = 1
	b.Write([]byte{0, 0, 0, 1})
	//operation-attributes-tag = 1 (begins an attribute-group)
	b.Write([]byte{1})

	//attributes-charset
	b.Write(AttributeByteString(0x47, "attributes-charset", "utf-8"))
	//attributes-natural-language
	b.Write(AttributeByteString(0x48, "attributes-natural-language", "en-us"))

	//end-of-attributes-tag = 3
	b.Write([]byte{3})

	return &b
}

func getPrintersRequest() *bytes.Buffer {
	var b bytes.Buffer
	//version = 3.0 newer than anything extant
	b.Write([]byte{2, 1})
	//operation-id = get-printer-attributes
	b.Write([]byte{0x40, 2})
	//request-id = 1
	b.Write([]byte{0, 0, 0, 1})
	//operation-attributes-tag = 1 (begins an attribute-group)
	b.Write([]byte{1})

	//attributes-charset
	b.Write(AttributeByteString(0x47, "attributes-charset", "utf-8"))
	//attributes-natural-language
	b.Write(AttributeByteString(0x48, "attributes-natural-language", "en-us"))

	//end-of-attributes-tag = 3
	b.Write([]byte{3})

	return &b
}

//TODO: Store everything except uri statically?
//Construct a minimal request that an IPP server will respond to
// IPP request encoding described at https://tools.ietf.org/html/rfc8010#section-3.1.1
func getPrinterAttributesRequest(uri string) *bytes.Buffer {
	var b bytes.Buffer
	// TODO: Explain whether and why we should use newest version, how does
	// old interact with new and vice versa?
	// FIXME: CUPS Server is simply returning the version number it's fed, which is sad :(
	// but it shouldn't do this if we connect to a particular printer, which by spec must
	// match a closest version number (Source: RFC 8011 Section 4.1.8)
	//version = 2.1 (newest as of 2018)
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
	b.Write(AttributeByteString(0x45, "printer-uri", convertURIToIPP(uri)))
	//requested-attributes
	b.Write(AttributeByteString(0x44, "requested-attributes", "all"))

	//end-of-attributes-tag = 3
	b.Write([]byte{3})

	return &b
}