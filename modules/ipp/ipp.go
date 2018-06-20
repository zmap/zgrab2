package ipp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

// Writes an "attribute-with-one-value" with the provided "value-tag", "name", and "value" to provided buffer
// attribute-with-one-value encoding described at https://tools.ietf.org/html/rfc8010#section-3.1.4
// Example (runnable from ipp_test.go):
//   Input: 0x47, "attributes-charset", "us-ascii"
//   Output: [71 0 18 97 116 116 114 105 98 117 116 101 115 45 99 104 97 114 115 101 116 0 8 117 115 45 97 115 99 105 105]
// TODO: Switch output and Example function to use hex.Dump()
// TODO: Should return an error when fed an invalid valueTag
func AttributeByteString(valueTag byte, name string, value string, target *bytes.Buffer) error {
	//special byte denoting value syntax
	binary.Write(target, binary.BigEndian, valueTag)

	if len(name) < (1 << 16) {
		//append 16-bit signed int denoting name length
		binary.Write(target, binary.BigEndian, int16(len(name)))

		//append name
		binary.Write(target, binary.BigEndian, []byte(name))
	} else {
		return errors.New("Name too long to encode.")
	}

	if len(value) < (1 << 16) {
		//append 16-bit signed int denoting value length
		binary.Write(target, binary.BigEndian, int16(len(value)))

		//append value
		binary.Write(target, binary.BigEndian, []byte(value))
	} else {
		return errors.New("Value too long to encode.")
	}

	return nil
}

func convertURIToIPP(uri string) string {
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		uri = strings.Replace(uri, "http", "ipp", 1)
	}
	// TODO: RFC claims that literal IP addresses are not valid uri's, but Wireshark IPP Capture example uses them
	// (Source: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=ipp.pcap)
	sections := strings.Split(uri, "/")
	if !strings.Contains(sections[2], ":") {
		sections[2] += ":631"
	}
	// TODO: Make sure that this properly constructs a valid uri
	if strings.HasPrefix(uri, "ipp://") {
		return uri
	}
	return "ipp://" + uri
}

func getPrintersRequest(major, minor int8) *bytes.Buffer {
	var b bytes.Buffer
	// Sending too new a version leads to a version-not-supported error, so we'll just send newest
	//version
	b.Write([]byte{byte(major), byte(minor)})
	//operation-id = get-printer-attributes
	b.Write([]byte{0x40, 2})
	//request-id = 1
	b.Write([]byte{0, 0, 0, 1})
	//operation-attributes-tag = 1 (begins an attribute-group)
	b.Write([]byte{1})

	// TODO: Handle error ocurring in any AttributeByteString call
	//attributes-charset
	AttributeByteString(0x47, "attributes-charset", "utf-8", &b)
	//attributes-natural-language
	AttributeByteString(0x48, "attributes-natural-language", "en-us", &b)

	//end-of-attributes-tag = 3
	b.Write([]byte{3})

	return &b
}

// TODO: Store everything except uri statically?
// Construct a minimal request that an IPP server will respond to
// IPP request encoding described at https://tools.ietf.org/html/rfc8010#section-3.1.1
func getPrinterAttributesRequest(major, minor int8, uri string) *bytes.Buffer {
	var b bytes.Buffer
	// Using newest version number, because we must provide a supported major version number
	// Object must reply to unsupported major version with
	//     "'server-error-version-not-supported' along with the closest version number that
	//     is supported" RFC 8011 4.1.8 https://tools.ietf.org/html/rfc8011#4.1.8
	// "In all cases, the IPP object MUST return the "version-number" value that it supports
	//     that is closest to the version number supplied by the Client in the request."
	// CUPS behavior defies the RFC. The response to a request with a bad version number should encode
	// the closest supported version number per RFC 8011 Section Appendix B.1.5.4 https://tools.ietf.org/html/rfc8011#appendix-B.1.5.4
	//version
	b.Write([]byte{byte(major), byte(minor)})
	//operation-id = get-printer-attributes
	b.Write([]byte{0, 0xb})
	//request-id = 1
	b.Write([]byte{0, 0, 0, 1})
	//operation-attributes-tag = 1 (begins an attribute-group)
	b.Write([]byte{1})

	// TODO: Handle error ocurring in any AttributeByteString call
	//attributes-charset
	AttributeByteString(0x47, "attributes-charset", "utf-8", &b)
	//attributes-natural-language
	AttributeByteString(0x48, "attributes-natural-language", "en-us", &b)
	//printer-uri
	AttributeByteString(0x45, "printer-uri", convertURIToIPP(uri), &b)
	//requested-attributes
	AttributeByteString(0x44, "requested-attributes", "all", &b)

	//end-of-attributes-tag = 3
	b.Write([]byte{3})

	return &b
}
