package ipp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Writes an "attribute-with-one-value" with the provided "value-tag", "name", and "value" to provided buffer
// attribute-with-one-value encoding described at https://tools.ietf.org/html/rfc8010#section-3.1.4
// Example (runnable from ipp_test.go):
//
//	Input: 0x47, "attributes-charset", "us-ascii"
//	Output: [71 0 18 97 116 116 114 105 98 117 116 101 115 45 99 104 97 114 115 101 116 0 8 117 115 45 97 115 99 105 105]
//
// TODO: Switch output and Example function to use hex.Dump()
// TODO: Should return an error when fed an invalid valueTag
func AttributeByteString(valueTag byte, name string, value string, target *bytes.Buffer) error {
	//special byte denoting value syntax
	binary.Write(target, binary.BigEndian, valueTag)

	if len(name) <= math.MaxInt16 && len(name) >= 0 {
		//append 16-bit signed int denoting name length
		binary.Write(target, binary.BigEndian, int16(len(name)))

		//append name
		binary.Write(target, binary.BigEndian, []byte(name))
	} else {
		// TODO: Log error somewhere
		return errors.New("Name wrong length to encode.")
	}

	if len(value) <= math.MaxInt16 && len(value) >= 0 {
		//append 16-bit signed int denoting value length
		binary.Write(target, binary.BigEndian, int16(len(value)))

		//append value
		binary.Write(target, binary.BigEndian, []byte(value))
	} else {
		// TODO: Log error somewhere
		return errors.New("Value wrong length to encode.")
	}

	return nil
}

// TODO: Eventually handle scheme-less urls, even though getHTTPURL will never construct one (we can use regex)
// TODO: RFC claims that literal IP addresses are not valid IPP uri's, but Wireshark IPP Capture example uses them
// (Source: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=ipp.pcap)
func ConvertURIToIPP(uriString string, tls bool) string {
	uri, err := url.Parse(uriString)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"url":   uriString,
		}).Debug("Failed to parse URL from string")
	}
	// TODO: Create a better condition than uri.Scheme == "" b/c url.Parse doesn't know whether there's a scheme
	if uri.Scheme == "" || uri.Scheme == "http" || uri.Scheme == "https" {
		if tls {
			uri.Scheme = "ipps"
		} else {
			uri.Scheme = "ipp"
		}
	}
	if !strings.Contains(uri.Host, ":") {
		uri.Host += ":631"
	}
	return uri.String()
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
func getPrinterAttributesRequest(major, minor int8, uri string, tls bool) *bytes.Buffer {
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
	AttributeByteString(0x45, "printer-uri", ConvertURIToIPP(uri, tls), &b)
	//requested-attributes
	AttributeByteString(0x44, "requested-attributes", "all", &b)

	//end-of-attributes-tag = 3
	b.Write([]byte{3})

	return &b
}
