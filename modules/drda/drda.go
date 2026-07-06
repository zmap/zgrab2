package drda

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// DRDA (Distributed Relational Database Architecture) is the wire protocol
// spoken by IBM DB2 (and Apache Derby / Informix). A DB2 server responds to an
// EXCSAT ("Exchange Server Attributes") request with an EXCSATRD reply carrying
// server-identifying attributes, all encoded in EBCDIC.

// DDM code points used by this module.
const (
	cpEXCSAT   = 0x1041 // Exchange Server Attributes (request)
	cpPRDID    = 0x112e // Product ID
	cpSRVCLSNM = 0x1147 // Server Class Name (platform, e.g. "QDB2/NT64")
	cpSRVRLSLV = 0x115a // Server Product Release Level (e.g. "SQL11013")
	cpEXTNAM   = 0x115e // External Name
	cpSRVNAM   = 0x116d // Server Name (instance name, e.g. "DB2")
	cpMGRLVLLS = 0x1404 // Manager-Level List
	cpEXCSATRD = 0x1443 // Exchange Server Attributes Reply Data

	ddmMagic     = 0xD0 // marks the start of every DDM message
	ddmHeaderLen = 10   // length(2) magic(1) format(1) corrId(2) length2(2) codePoint(2)
)

// mgrlvlls is the standard Manager-Level List sent by nmap/Shodan in EXCSAT.
var mgrlvlls = mustHex("1403000724070008240f00081440000814740008")

// e2a is the EBCDIC (code page 500) -> ASCII translation table used to decode
// the string attributes returned in the EXCSATRD reply.
var e2a = mustHex("000102039C09867F978D8E0B0C0D0E0F" +
	"101112139D8508871819928F1C1D1E1F" +
	"80818283840A171B88898A8B8C050607" +
	"909116939495960498999A9B14159E1A" +
	"20A0A1A2A3A4A5A6A7A8D52E3C282B7C" +
	"26A9AAABACADAEAFB0B121242A293B5E" +
	"2D2FB2B3B4B5B6B7B8B9E52C255F3E3F" +
	"BABBBCBDBEBFC0C1C2603A2340273D22" +
	"C3616263646566676869C4C5C6C7C8C9" +
	"CA6A6B6C6D6E6F707172CBCCCDCECFD0" +
	"D17E737475767778797AD2D3D45BD6D7" +
	"D8D9DADBDCDDDEDFE0E1E2E3E45DE6E7" +
	"7B414243444546474849E8E9EAEBECED" +
	"7D4A4B4C4D4E4F505152EEEFF0F1F2F3" +
	"5C9F535455565758595AF4F5F6F7F8F9" +
	"30313233343536373839FAFBFCFDFEFF")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("drda: invalid hex constant %q: %v", s, err))
	}
	return b
}

// ebcdicToASCII decodes an EBCDIC byte slice into an ASCII string.
func ebcdicToASCII(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = e2a[c]
	}
	return string(out)
}

// buildEXCSAT builds the DRDA EXCSAT probe packet. It mirrors the request sent
// by nmap's drda-info and Shodan: empty EXTNAM/SRVNAM/SRVRLSLV/SRVCLSNM plus the
// standard MGRLVLLS.
func buildEXCSAT() []byte {
	var params []byte
	appendParam := func(cp int, data []byte) {
		p := make([]byte, 4+len(data))
		binary.BigEndian.PutUint16(p[0:2], uint16(4+len(data)))
		binary.BigEndian.PutUint16(p[2:4], uint16(cp))
		copy(p[4:], data)
		params = append(params, p...)
	}
	appendParam(cpEXTNAM, nil)
	appendParam(cpSRVNAM, nil)
	appendParam(cpSRVRLSLV, nil)
	appendParam(cpMGRLVLLS, mgrlvlls)
	appendParam(cpSRVCLSNM, nil)

	total := ddmHeaderLen + len(params)
	ddm := make([]byte, ddmHeaderLen)
	binary.BigEndian.PutUint16(ddm[0:2], uint16(total))   // Length
	ddm[2] = ddmMagic                                     // Magic (0xD0)
	ddm[3] = 0x01                                         // Format (no CHAINED bit: this is a lone request)
	binary.BigEndian.PutUint16(ddm[4:6], 1)               // CorrelationID
	binary.BigEndian.PutUint16(ddm[6:8], uint16(total-6)) // Length2
	binary.BigEndian.PutUint16(ddm[8:10], cpEXCSAT)       // CodePoint

	return append(ddm, params...)
}

// excsatrd holds the ASCII-decoded attributes parsed out of an EXCSATRD reply.
type excsatrd struct {
	externalName string
	serverClass  string
	serverName   string
	releaseLevel string
	productID    string
}

// parseEXCSATRD scans a DRDA response for an EXCSATRD DDM and extracts its
// string attributes, decoding each from EBCDIC to ASCII. Returns false if no
// EXCSATRD DDM is present.
func parseEXCSATRD(data []byte) (*excsatrd, bool) {
	// Walk the (possibly chained) top-level DDM messages.
	for pos := 0; pos+ddmHeaderLen <= len(data); {
		ddmLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		magic := data[pos+2]
		codePoint := int(binary.BigEndian.Uint16(data[pos+8 : pos+10]))
		if magic != ddmMagic || ddmLen < ddmHeaderLen || pos+ddmLen > len(data) {
			return nil, false
		}
		if codePoint != cpEXCSATRD {
			pos += ddmLen
			continue
		}

		res := &excsatrd{}
		// Parse the nested parameters that fill the rest of this DDM.
		p := pos + ddmHeaderLen
		end := pos + ddmLen
		for p+4 <= end {
			paramLen := int(binary.BigEndian.Uint16(data[p : p+2]))
			paramCP := int(binary.BigEndian.Uint16(data[p+2 : p+4]))
			if paramLen < 4 || p+paramLen > end {
				break
			}
			value := ebcdicToASCII(data[p+4 : p+paramLen])
			switch paramCP {
			case cpEXTNAM:
				res.externalName = value
			case cpSRVCLSNM:
				res.serverClass = value
			case cpSRVNAM:
				res.serverName = value
			case cpSRVRLSLV:
				res.releaseLevel = value
			case cpPRDID:
				res.productID = value
			}
			p += paramLen
		}
		return res, true
	}
	return nil, false
}

// versionFromReleaseLevel converts a DB2 product release level such as
// "SQL11013" into a human-readable version like "11.01.3". Returns "" if the
// input does not match the expected form.
func versionFromReleaseLevel(rel string) string {
	if len(rel) < 8 || rel[:3] != "SQL" {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s", rel[3:5], rel[5:7], rel[7:8])
}
