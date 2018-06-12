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

func reverse(b []byte) []byte {
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-1-i] = b[len(b)-1-i], b[i]
	}
	return b
}

//FIXME: Clean this up, and use binary package to handle endianness in the correct order
//FIXME: Make sure uint isn't messing anything up here, since they should be signed.
func attributeByteString(syntaxTag byte, name string, value string) []byte {
	//special bytestring denoting value syntax
	b := []byte{syntaxTag}
	l := make([]byte, 2)
	binary.PutUvarint(l, uint64(len(name)))
	l = reverse(l)
	b = append(b, l...)
	b = append(b, []byte(name)...)

	l = make([]byte, 2)
	binary.PutUvarint(l, uint64(len(value)))
	l = reverse(l)
	b = append(b, l...)
	b = append(b, []byte(value)...)
	return b
}

//TODO: Dynamically create nothing except uri?
//Construct a minimal request that an IPP server will respond to
func getPrinterAttributesRequest(uri string) bytes.Buffer {
	var b bytes.Buffer
	//version 2.1 (newest as of 2018)
	b.Write([]byte{2, 1})
	//operation-id = get-printer-attributes
	b.Write([]byte{0, 0xb})
	//request-id = 1
	b.Write([]byte{0, 0, 0, 1})
	//operation-attributes-tag = 1
	b.Write([]byte{1})

	//attributes-charset
	b.Write(attributeByteString(0x47, "attributes-charset", "utf-8"))
	//attributes-natural-language
	b.Write(attributeByteString(0x48, "attributes-natural-language", "en-us"))
	//printer-uri
	b.Write(attributeByteString(0x45, "printer-uri", uri))
	//requested-attributes
	b.Write(attributeByteString(0x44, "requested-attributes", "all"))

	//end-of-attributes-tag = 3
	b.Write([]byte{3})

	return b
}