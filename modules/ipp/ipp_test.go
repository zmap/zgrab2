package ipp

import (
	"bytes"
	"fmt"
)

func ExampleAttributeByteString() {
	var buf bytes.Buffer
	if err := AttributeByteString(0x47, "attributes-charset", "us-ascii", &buf); err == nil {
		fmt.Println(buf.Bytes())
	}
	// Output: [71 0 18 97 116 116 114 105 98 117 116 101 115 45 99 104 97 114 115 101 116 0 8 117 115 45 97 115 99 105 105]
}

func ExampleConvertURIToIPP() {
	fmt.Println(ConvertURIToIPP("http://www.google.com:631/ipp", false))
	fmt.Println(ConvertURIToIPP("https://www.google.com:631/ipp", true))
	fmt.Println(ConvertURIToIPP("http://www.google.com/ipp", false))
	fmt.Println(ConvertURIToIPP("https://www.google.com/ipp", true))
	fmt.Println(ConvertURIToIPP("http://www.google.com:631", false))
	fmt.Println(ConvertURIToIPP("https://www.google.com:631", true))
	// TODO: Eventually test for scheme-less urls, but getHTTPURL will never construct one
	//fmt.Println(ConvertURIToIPP("www.google.com:631/ipp", false))
	//fmt.Println(ConvertURIToIPP("www.google.com:631/ipp", true))
	// Output:
	// ipp://www.google.com:631/ipp
	// ipps://www.google.com:631/ipp
	// ipp://www.google.com:631/ipp
	// ipps://www.google.com:631/ipp
	// ipp://www.google.com:631
	// ipps://www.google.com:631
}
