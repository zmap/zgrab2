package oracle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// debugging -- interleave hex dumps of expected/actual, highlight differences
func interleave(expected, actual []byte) string {
	ret := make([]string, 0)
	e := strings.Split(string(hex.Dump(expected)), "\n")
	a := strings.Split(string(hex.Dump(actual)), "\n")
	n := max(len(e), len(a))
	for i := 0; i < n-1; i++ {
		var ei, ai string = "", ""
		if i < len(e) {
			ei = e[i]
		}
		if i < len(a) {
			ai = a[i]
		}
		m := max(len(ei), len(ai))
		diff := make([]byte, m)
		for j := 1; j < m; j++ {
			var aij, eij byte = 32, 32
			if j < len(ai) {
				aij = ai[j]
			}
			if j < len(ei) {
				eij = ei[j]
			}
			if aij != eij {
				diff[j] = '!'
			}
		}
		ret = append(ret, "E: "+ei)
		ret = append(ret, "A: "+ai)
		ret = append(ret, "D: "+string(diff))
	}
	return strings.Join(ret, "\n")
}

func fromHex(h string) []byte {
	bytes := strings.Fields(h)
	ret := make([]byte, len(bytes))
	for i, v := range bytes {
		b, err := strconv.ParseUint(v, 16, 8)
		if err != nil {
			panic(err)
		}
		ret[i] = byte(b)
	}
	return ret
}

var validHeaders = map[string]TNSHeader{
	"00 08 00 01 02 03 00 45": TNSHeader{
		Length:         8,
		PacketChecksum: 1,
		Type:           2,
		Flags:          3,
		HeaderChecksum: 0x45,
	},
	"f2 1e 01 00 07 06 76 54": TNSHeader{
		Length:         0xF21E,
		PacketChecksum: 0x0100,
		Type:           0x07,
		Flags:          0x06,
		HeaderChecksum: 0x7654,
	},
}

type TestCase struct {
	Value    *TNSPacket
	Encoding string
}

var validTNSData = map[string]TestCase{
	"00.empty": TestCase{
		Encoding: "00 0A 00 00 06 00 00 00  80 00",
		Value: &TNSPacket{
			Header: &TNSHeader{
				Length:         0x0A,
				PacketChecksum: 0,
				Flags:          0,
				Type:           PacketTypeData,
				HeaderChecksum: 0,
			},
			Body: &TNSData{
				DataFlags: 0x8000,
				Data:      []byte{},
			},
		},
	},
	"00.trivial": TestCase{
		Encoding: "00 10 00 00 06 00 00 00  00 01 31 32 33 34 35 36",
		Value: &TNSPacket{
			Header: &TNSHeader{
				Length:         0x10,
				PacketChecksum: 0,
				Flags:          0,
				Type:           PacketTypeData,
				HeaderChecksum: 0,
			},
			Body: &TNSData{
				DataFlags: 1,
				Data:      []byte("123456"),
			},
		},
	},
	"01.NSN.Request": TestCase{
		Encoding: "00 a8 00 00 06 00 00 00  00 00 de ad be ef 00 9e " + /* ................ */
			"0a 20 03 00 00 04 00 00  04 00 03 00 00 00 00 00 " + /* . .............. */
			"04 00 05 0a 20 03 00 00  08 00 01 00 00 04 ec 19 " + /* .... ........... */
			"2c 7b 4c 00 12 00 01 de  ad be ef 00 03 00 00 00 " + /* ,{L............. */
			"04 00 04 00 01 00 01 00  02 00 01 00 05 00 00 00 " + /* ................ */
			"00 00 04 00 05 0a 20 03  00 00 02 00 03 e0 e1 00 " + /* ...... ......... */
			"02 00 06 fc ff 00 01 00  02 01 00 03 00 00 4e 54 " + /* ..............NT */
			"53 00 02 00 02 00 00 00  00 00 04 00 05 0a 20 03 " + /* S............. . */
			"00 00 0c 00 01 00 11 06  10 0c 0f 0a 0b 08 02 01 " + /* ................ */
			"03 00 03 00 02 00 00 00  00 00 04 00 05 0a 20 03 " + /* .............. . */
			"00 00 03 00 01 00 03 01 ", /* ........ */
		Value: &TNSPacket{
			Header: &TNSHeader{
				Length:         0x00a8,
				PacketChecksum: 0,
				Flags:          0,
				Type:           PacketTypeData,
				HeaderChecksum: 0,
			},
			Body: &TNSData{
				DataFlags: 0,
				Data: (&TNSDataNSN{
					ID:      0xdeadbeef,
					Version: EncodeReleaseVersion("10.2.0.3.0"),
					Options: NSNOptions(0),
					Services: []NSNService{
						NSNService{
							Type: 4,
							Values: []NSNValue{
								*NSNValueVersion("10.2.0.3.0"),
								*NSNValueBytes(fromHex("00 00 04 ec 19 2c 7b 4c")),
								*NSNValueBytes(fromHex("de ad be ef 00 03 00 00 00 04 00 04 00 01 00 01 00 02")),
							},
							Marker: 0,
						},
						NSNService{
							Type: 1,
							Values: []NSNValue{
								*NSNValueVersion("10.2.0.3.0"),
								NSNValue{
									Type:  3,
									Value: fromHex("e0 e1"),
								},
								NSNValue{
									Type:  6,
									Value: fromHex("fc ff"),
								},
								NSNValue{
									Type:  2,
									Value: fromHex("01"),
								},
								NSNValue{
									Type:  0,
									Value: []byte("NTS"),
								},
							},
							Marker: 0,
						},
						NSNService{
							Type: 2,
							Values: []NSNValue{
								*NSNValueVersion("10.2.0.3.0"),
								NSNValue{
									Type:  1,
									Value: fromHex("00 11 06 10 0c 0f 0a 0b 08 02 01 03"),
								},
							},
							Marker: 0,
						},
						NSNService{
							Type: 3,
							Values: []NSNValue{
								*NSNValueVersion("10.2.0.3.0"),
								NSNValue{
									Type:  1,
									Value: fromHex("00 03 01"),
								},
							},
						},
					},
				}).Encode(),
			},
		},
	},
}

var validTNSConnect = map[string]TestCase{
	"01. 013A-0139": TestCase{
		Encoding: "00 ca 00 00 01 00 00 00  01 3a 01 2c 0c 41 20 00 " + /* .........:.,.A . */
			"ff ff 7f 08 00 00 01 00  00 90 00 3a 00 00 08 00 " + /* ...........:.... */
			"41 41 00 00 00 00 00 00  00 00 00 00 00 00 00 00 " + /* AA.............. */
			"00 00 00 00 00 00 00 00  00 00 28 44 45 53 43 52 " + /* ..........(DESCR */
			"49 50 54 49 4f 4e 3d 28  43 4f 4e 4e 45 43 54 5f " + /* IPTION=(CONNECT_ */
			"44 41 54 41 3d 28 53 45  52 56 49 43 45 5f 4e 41 " + /* DATA=(SERVICE_NA */
			"4d 45 3d 63 6b 64 62 29  28 43 49 44 3d 28 50 52 " + /* ME=ckdb)(CID=(PR */
			"4f 47 52 41 4d 3d 67 73  71 6c 29 28 48 4f 53 54 " + /* OGRAM=gsql)(HOST */
			"3d 4d 63 41 66 65 65 29  28 55 53 45 52 3d 72 6f " + /* =McAfee)(USER=ro */
			"6f 74 29 29 29 28 41 44  44 52 45 53 53 3d 28 50 " + /* ot)))(ADDRESS=(P */
			"52 4f 54 4f 43 4f 4c 3d  54 43 50 29 28 48 4f 53 " + /* ROTOCOL=TCP)(HOS */
			"54 3d 31 30 2e 31 2e 35  30 2e 31 34 29 28 50 4f " + /* T=10.1.50.14)(PO */
			"52 54 3d 31 35 32 31 29  29 29 ", /* RT=1521))) */
		Value: &TNSPacket{
			Header: &TNSHeader{Length: 0x00ca, PacketChecksum: 0, Type: PacketTypeConnect, Flags: 0, HeaderChecksum: 0},
			Body: &TNSConnect{
				Version:              0x013a,
				MinVersion:           0x012c,
				GlobalServiceOptions: SOHeaderChecksum | SOFullDuplex | SOUnknown0040 | SOUnknown0001, // (0x0c41)
				SDU:                  0x2000,
				TDU:                  0xffff,
				ProtocolCharacteristics: NTPCConfirmedRelease | NTPCTDUBasedIO | NTPCSpawnerRunning | NTPCDataTest | NTPCCallbackIO | NTPCAsyncIO | NTPCPacketIO | NTPCGenerateSIGURG, // 0x7F08
				MaxBeforeAck:            0,
				ByteOrder:               defaultByteOrder,
				DataLength:              0x0090,
				DataOffset:              0x003A,
				MaxResponseSize:         0x00000800,
				ConnectFlags0:           CFUnknown40 | CFServicesWanted,
				ConnectFlags1:           CFUnknown40 | CFServicesWanted,
				CrossFacility0:          0,
				CrossFacility1:          0,
				ConnectionID0:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
				ConnectionID1:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
				Unknown3A:               []byte{},
				ConnectionString:        "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ckdb)(CID=(PROGRAM=gsql)(HOST=McAfee)(USER=root)))(ADDRESS=(PROTOCOL=TCP)(HOST=10.1.50.14)(PORT=1521)))",
			},
		},
	},
	"02. 138-138": TestCase{
		Encoding: "01 00 00 00 01 04 00 00  01 38 01 2c 00 00 08 00 " + /* .........8.,.... */
			"7f ff 86 0e 00 00 01 00  00 c6 00 3a 00 00 02 00 " + /* ...........:.... */
			"61 61 00 00 00 00 00 00  00 00 00 00 04 10 00 00 " + /* aa.............. */
			"00 03 00 00 00 00 00 00  00 00 28 44 45 53 43 52 " + /* ..........(DESCR */
			"49 50 54 49 4f 4e 3d 28  41 44 44 52 45 53 53 3d " + /* IPTION=(ADDRESS= */
			"28 50 52 4f 54 4f 43 4f  4c 3d 54 43 50 29 28 48 " + /* (PROTOCOL=TCP)(H */
			"4f 53 54 3d 31 39 32 2e  31 36 38 2e 31 2e 32 32 " + /* OST=192.168.1.22 */
			"31 29 28 50 4f 52 54 3d  31 35 32 31 29 29 28 43 " + /* 1)(PORT=1521))(C */
			"4f 4e 4e 45 43 54 5f 44  41 54 41 3d 28 53 49 44 " + /* ONNECT_DATA=(SID */
			"3d 76 6f 69 64 29 28 53  45 52 56 45 52 3d 44 45 " + /* =void)(SERVER=DE */
			"44 49 43 41 54 45 44 29  28 43 49 44 3d 28 50 52 " + /* DICATED)(CID=(PR */
			"4f 47 52 41 4d 3d 46 3a  5c 6f 72 61 63 6c 65 5c " + /* OGRAM=F:\oracle\ */
			"6f 72 61 39 32 5c 62 69  6e 5c 73 71 6c 70 6c 75 " + /* ora92\bin\sqlplu */
			"73 2e 65 78 65 29 28 48  4f 53 54 3d 46 41 4e 47 " + /* s.exe)(HOST=FANG */
			"48 4f 4e 47 5a 48 41 4f  29 28 55 53 45 52 3d 41 " + /* HONGZHAO)(USER=A */
			"64 6d 69 6e 69 73 74 72  61 74 6f 72 29 29 29 29 ", /* dministrator)))) */
		Value: &TNSPacket{
			Header: &TNSHeader{Length: 0x0100, PacketChecksum: 0, Type: PacketTypeConnect, Flags: 0x04, HeaderChecksum: 0},
			Body: &TNSConnect{
				Version:              0x0138,
				MinVersion:           0x012c,
				GlobalServiceOptions: 0,
				SDU:                  0x0800,
				TDU:                  0x7fff,
				ProtocolCharacteristics: NTPCHangon | NTPCCallbackIO | NTPCAsyncIO | NTPCGenerateSIGURG | NTPCUrgentIO | NTPCFullDuplex, // 0x860e
				MaxBeforeAck:            0,
				ByteOrder:               defaultByteOrder,
				DataLength:              0x00c6,
				DataOffset:              0x003a,
				MaxResponseSize:         0x00000200,
				ConnectFlags0:           CFUnknown40 | CFUnknown20 | CFServicesWanted,
				ConnectFlags1:           CFUnknown40 | CFUnknown20 | CFServicesWanted,
				CrossFacility0:          0,
				CrossFacility1:          0,
				ConnectionID0:           [8]byte{0x00, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x03},
				ConnectionID1:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
				Unknown3A:               []byte{},
				ConnectionString:        "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.1.221)(PORT=1521))(CONNECT_DATA=(SID=void)(SERVER=DEDICATED)(CID=(PROGRAM=F:\\oracle\\ora92\\bin\\sqlplus.exe)(HOST=FANGHONGZHAO)(USER=Administrator))))",
			},
		},
	},
	"03. 138-138": TestCase{
		Encoding: "00 ec 00 00 01 04 00 00  01 38 01 2c 00 00 08 00 " + /* .........8.,.... */
			"7f ff 86 0e 00 00 01 00  00 b2 00 3a 00 00 02 00 " + /* ...........:.... */
			"61 61 00 00 00 00 00 00  00 00 00 00 10 ec 00 00 " + /* aa.............. */
			"00 05 00 00 00 00 00 00  00 00 28 44 45 53 43 52 " + /* ..........(DESCR */
			"49 50 54 49 4f 4e 3d 28  41 44 44 52 45 53 53 3d " + /* IPTION=(ADDRESS= */
			"28 50 52 4f 54 4f 43 4f  4c 3d 54 43 50 29 28 48 " + /* (PROTOCOL=TCP)(H */
			"4f 53 54 3d 41 41 29 28  50 4f 52 54 3d 31 35 32 " + /* OST=AA)(PORT=152 */
			"31 29 29 28 43 4f 4e 4e  45 43 54 5f 44 41 54 41 " + /* 1))(CONNECT_DATA */
			"3d 28 53 49 44 3d 76 6f  69 64 29 28 53 45 52 56 " + /* =(SID=void)(SERV */
			"45 52 3d 44 45 44 49 43  41 54 45 44 29 28 43 49 " + /* ER=DEDICATED)(CI */
			"44 3d 28 50 52 4f 47 52  41 4d 3d 44 3a 5c 6f 72 " + /* D=(PROGRAM=D:\or */
			"61 63 6c 65 5c 6f 72 61  39 32 5c 62 69 6e 5c 73 " + /* acle\ora92\bin\s */
			"71 6c 70 6c 75 73 2e 65  78 65 29 28 48 4f 53 54 " + /* qlplus.exe)(HOST */
			"3d 48 49 4e 47 45 2d 48  41 4e 59 46 29 28 55 53 " + /* =HINGE-HANYF)(US */
			"45 52 3d 68 61 6e 79 66  29 29 29 29 ", /* ER=hanyf)))) */
		Value: &TNSPacket{
			Header: &TNSHeader{Length: 0x00EC, PacketChecksum: 0, Type: PacketTypeConnect, Flags: 0x04, HeaderChecksum: 0},
			Body: &TNSConnect{
				Version:              0x0138,
				MinVersion:           0x012c,
				GlobalServiceOptions: 0,
				SDU:                  0x0800,
				TDU:                  0x7fff,
				ProtocolCharacteristics: NTPCHangon | NTPCCallbackIO | NTPCAsyncIO | NTPCGenerateSIGURG | NTPCUrgentIO | NTPCFullDuplex, // 0x860e
				MaxBeforeAck:            0,
				ByteOrder:               defaultByteOrder,
				DataLength:              0x00b2,
				DataOffset:              0x003a,
				MaxResponseSize:         0x00000200,
				ConnectFlags0:           CFUnknown40 | CFUnknown20 | CFServicesWanted,
				ConnectFlags1:           CFUnknown40 | CFUnknown20 | CFServicesWanted,
				CrossFacility0:          0,
				CrossFacility1:          0,
				ConnectionID0:           [8]byte{0x00, 0x00, 0x10, 0xec, 0x00, 0x00, 0x00, 0x05},
				ConnectionID1:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
				Unknown3A:               []byte{},
				ConnectionString:        "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=AA)(PORT=1521))(CONNECT_DATA=(SID=void)(SERVER=DEDICATED)(CID=(PROGRAM=D:\\oracle\\ora92\\bin\\sqlplus.exe)(HOST=HINGE-HANYF)(USER=hanyf))))",
			},
		},
	},
	"unknown": TestCase{
		Encoding: "00 d7 00 00 01 00 00 00  01 3b 01 2c 0c 41 20 00 " + /* .........;.,.A . */
			"ff ff 7f 08 00 00 01 00  00 91 00 46 00 00 08 00 " + /* ...........F.... */
			"41 41 00 00 00 00 00 00  00 00 00 00 00 00 00 00 " + /* AA.............. */
			"00 00 00 00 00 00 00 00  00 00 00 00 20 00 00 20 " + /* ............ ..  */
			"00 00 00 00 00 00 28 44  45 53 43 52 49 50 54 49 " + /* ......(DESCRIPTI */
			"4f 4e 3d 28 43 4f 4e 4e  45 43 54 5f 44 41 54 41 " + /* ON=(CONNECT_DATA */
			"3d 28 53 49 44 3d 6f 72  63 6c 31 31 67 29 28 43 " + /* =(SID=orcl11g)(C */
			"49 44 3d 28 50 52 4f 47  52 41 4d 3d 73 71 6c 70 " + /* ID=(PROGRAM=sqlp */
			"6c 75 73 40 6b 61 6c 69  29 28 48 4f 53 54 3d 6b " + /* lus@kali)(HOST=k */
			"61 6c 69 29 28 55 53 45  52 3d 72 6f 6f 74 29 29 " + /* ali)(USER=root)) */
			"29 28 41 44 44 52 45 53  53 3d 28 50 52 4f 54 4f " + /* )(ADDRESS=(PROTO */
			"43 4f 4c 3d 54 43 50 29  28 48 4f 53 54 3d 31 30 " + /* COL=TCP)(HOST=10 */
			"2e 30 2e 37 32 2e 31 31  33 29 28 50 4f 52 54 3d " + /* .0.72.113)(PORT= */
			"31 35 32 31 29 29 29 ",
		Value: &TNSPacket{
			Header: &TNSHeader{Length: 0x00d7, PacketChecksum: 0, Type: PacketTypeConnect, Flags: 0, HeaderChecksum: 0},
			Body: &TNSConnect{
				Version:              0x013b,
				MinVersion:           0x012c,
				GlobalServiceOptions: SOHeaderChecksum | SOFullDuplex | SOUnknown0040 | SOUnknown0001, // (0x0c41)
				SDU:                  0x2000,
				TDU:                  0xffff,
				ProtocolCharacteristics: NTPCConfirmedRelease | NTPCTDUBasedIO | NTPCSpawnerRunning | NTPCDataTest | NTPCCallbackIO | NTPCAsyncIO | NTPCPacketIO | NTPCGenerateSIGURG, // 0x7F08
				MaxBeforeAck:            0,
				ByteOrder:               defaultByteOrder,
				DataLength:              0x0091,
				DataOffset:              0x0046, // points past the 12 bytes of \x00/\x20 at the start
				MaxResponseSize:         0x00000800,
				ConnectFlags0:           CFUnknown40 | CFServicesWanted,
				ConnectFlags1:           CFUnknown40 | CFServicesWanted,
				CrossFacility0:          0,
				CrossFacility1:          0,
				ConnectionID0:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
				ConnectionID1:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
				Unknown3A:               []byte{0x00, 0x00, 0x20, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				ConnectionString:        "(DESCRIPTION=(CONNECT_DATA=(SID=orcl11g)(CID=(PROGRAM=sqlplus@kali)(HOST=kali)(USER=root)))(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.72.113)(PORT=1521)))",
			},
		},
	},
	"unknown3a": TestCase{
		Encoding: "00 d7 00 00 01 00 00 00  01 3b 01 2c 0c 41 20 00 " + /* .........;.,.A . */
			"ff ff 7f 08 00 00 01 00  00 91 00 46 00 00 08 00 " + /* ...........F.... */
			"41 41 00 00 00 00 00 00  00 00 00 00 00 00 00 00 " + /* AA.............. */
			"00 00 00 00 00 00 00 00  00 00 12 34 56 78 9a bc " + /* ............ ..  */
			"de fe dc ba 98 76 28 44  45 53 43 52 49 50 54 49 " + /* ......(DESCRIPTI */
			"4f 4e 3d 28 43 4f 4e 4e  45 43 54 5f 44 41 54 41 " + /* ON=(CONNECT_DATA */
			"3d 28 53 49 44 3d 6f 72  63 6c 31 31 67 29 28 43 " + /* =(SID=orcl11g)(C */
			"49 44 3d 28 50 52 4f 47  52 41 4d 3d 73 71 6c 70 " + /* ID=(PROGRAM=sqlp */
			"6c 75 73 40 6b 61 6c 69  29 28 48 4f 53 54 3d 6b " + /* lus@kali)(HOST=k */
			"61 6c 69 29 28 55 53 45  52 3d 72 6f 6f 74 29 29 " + /* ali)(USER=root)) */
			"29 28 41 44 44 52 45 53  53 3d 28 50 52 4f 54 4f " + /* )(ADDRESS=(PROTO */
			"43 4f 4c 3d 54 43 50 29  28 48 4f 53 54 3d 31 30 " + /* COL=TCP)(HOST=10 */
			"2e 30 2e 37 32 2e 31 31  33 29 28 50 4f 52 54 3d " + /* .0.72.113)(PORT= */
			"31 35 32 31 29 29 29 ",
		Value: &TNSPacket{
			Header: &TNSHeader{Length: 0x00d7, PacketChecksum: 0, Type: PacketTypeConnect, Flags: 0, HeaderChecksum: 0},
			Body: &TNSConnect{
				Version:              0x013b,
				MinVersion:           0x012c,
				GlobalServiceOptions: SOHeaderChecksum | SOFullDuplex | SOUnknown0040 | SOUnknown0001, // (0x0c41)
				SDU:                  0x2000,
				TDU:                  0xffff,
				ProtocolCharacteristics: NTPCConfirmedRelease | NTPCTDUBasedIO | NTPCSpawnerRunning | NTPCDataTest | NTPCCallbackIO | NTPCAsyncIO | NTPCPacketIO | NTPCGenerateSIGURG, // 0x7F08
				MaxBeforeAck:            0,
				ByteOrder:               defaultByteOrder,
				DataLength:              0x0091,
				DataOffset:              0x0046,
				MaxResponseSize:         0x00000800,
				ConnectFlags0:           CFUnknown40 | CFServicesWanted,
				ConnectFlags1:           CFUnknown40 | CFServicesWanted,
				CrossFacility0:          0,
				CrossFacility1:          0,
				ConnectionID0:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
				ConnectionID1:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
				Unknown3A:               []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xfe, 0xdc, 0xba, 0x98, 0x76},
				ConnectionString:        "(DESCRIPTION=(CONNECT_DATA=(SID=orcl11g)(CID=(PROGRAM=sqlplus@kali)(HOST=kali)(USER=root)))(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.72.113)(PORT=1521)))",
			},
		},
	},
}

var validTNSAccept = map[string]TestCase{
	"01. 013A-0139": TestCase{
		Encoding: "00 20 00 00 02 00 00 00  01 39 00 00 08 00 7f ff " + /* . .......9...... */
			"01 00 00 00 00 20 61 61  00 00 00 00 00 00 00 00 ", /* ..... aa........ */
		Value: &TNSPacket{
			Header: &TNSHeader{Length: 0x0020, PacketChecksum: 0, Type: PacketTypeAccept, Flags: 0, HeaderChecksum: 0},
			Body: &TNSAccept{
				Version:              0x0139,
				GlobalServiceOptions: 0,
				SDU:                  0x0800,
				TDU:                  0x7fff,
				ByteOrder:            defaultByteOrder,
				DataLength:           0,
				DataOffset:           0x20,
				ConnectFlags0:        CFUnknown40 | CFUnknown20 | CFServicesWanted,
				ConnectFlags1:        CFUnknown40 | CFUnknown20 | CFServicesWanted,
				Unknown18:            []byte{0, 0, 0, 0, 0, 0, 0, 0},
				AcceptData:           []byte{},
			},
		},
	},
}

func serialize(val interface{}) []byte {
	ret, err := json.Marshal(val)
	if err != nil {
		panic(err)
	}
	return ret
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TODO: TNSRedirect
// TODO: Invalid cases

func TestTNSHeaderEncode(t *testing.T) {
	for hex, header := range validHeaders {
		bin := fromHex(hex)
		encoded := header.Encode()
		if !bytes.Equal(bin, encoded) {
			t.Errorf("TNSHeader.Encode mismatch:[\n%s\n]", interleave(bin, encoded))
		}
		decoded, rest, err := DecodeTNSHeader(bin)
		if err != nil {
			t.Fatalf("Decode error:  %v", err)
		}
		if len(rest) > 0 {
			t.Fatalf("Leftover data (%d bytes)", len(rest))
		}
		jsonHeader := serialize(header)
		jsonDecoded := serialize(decoded)
		if !bytes.Equal(jsonHeader, jsonDecoded) {
			t.Errorf("TNSHeader.Read mismatch:[\n%s\n]", interleave(jsonHeader, jsonDecoded))
		}
	}
}

func TestTNSConnect(t *testing.T) {
	for tag, info := range validTNSConnect {
		bin := fromHex(info.Encoding)
		encoded := info.Value.Encode()
		if !bytes.Equal(bin, encoded) {
			t.Errorf("%s: TNSConnect.Encode mismatch:[\n%s\n]", tag, interleave(bin, encoded))
		}
		reader := getSliceReader(bin)
		response, err := ReadTNSPacket(reader)
		if err != nil {
			t.Fatalf("%s: Error reading TNSConnect packet: %v", tag, err)
		}
		// TODO: check header
		decoded, ok := response.Body.(*TNSConnect)
		if !ok {
			t.Fatalf("%s: Read wrong packet: %v", tag, response.Body)
		}
		jsonPacket := serialize(info.Value.Body)
		jsonDecoded := serialize(decoded)
		if !bytes.Equal(jsonPacket, jsonDecoded) {
			t.Errorf("%s: TNSConnect.Read mismatch:[\n%s\n]", tag, interleave(jsonPacket, jsonDecoded))
		}
		if len(reader.Data) > 0 {
			t.Errorf("%s: TNSConnect.Read: %d bytes left over", tag, len(reader.Data))
		}
	}
}

func TestTNSAccept(t *testing.T) {
	for tag, info := range validTNSAccept {
		bin := fromHex(info.Encoding)
		encoded := info.Value.Encode()
		if !bytes.Equal(bin, encoded) {
			t.Errorf("%s: TNSAccept.Encode mismatch:[\n%s\n]", tag, interleave(bin, encoded))
		}
		reader := getSliceReader(bin)
		response, err := ReadTNSPacket(reader)
		if err != nil {
			t.Fatalf("%s: Error reading TNSAccept packet: %v", tag, err)
		}
		// TODO: check header
		decoded, ok := response.Body.(*TNSAccept)
		if !ok {
			t.Fatalf("%s: Read wrong packet: %v", tag, response.Body)
		}
		jsonPacket := serialize(info.Value.Body)
		jsonDecoded := serialize(decoded)
		if !bytes.Equal(jsonPacket, jsonDecoded) {
			t.Errorf("%s: TNSAccept.Read mismatch:[\n%s\n]", tag, interleave(jsonPacket, jsonDecoded))
		}
		if len(reader.Data) > 0 {
			t.Errorf("%s: TNSAccept.Read: %d bytes left over", tag, len(reader.Data))
		}
	}
}

func TestTNSData(t *testing.T) {
	for tag, info := range validTNSData {
		bin := fromHex(info.Encoding)
		encoded := info.Value.Encode()
		if !bytes.Equal(bin, encoded) {
			t.Errorf("%s: TNSData.Encode mismatch:[\n%s\n]", tag, interleave(bin, encoded))
		}
		reader := getSliceReader(bin)
		response, err := ReadTNSPacket(reader)
		if err != nil {
			t.Fatalf("%s: Error reading TNSData packet: %v", tag, err)
		}
		// TODO: check header
		decoded, ok := response.Body.(*TNSData)
		if !ok {
			t.Fatalf("%s: Read wrong packet: %v", tag, response.Body)
		}
		jsonPacket := serialize(info.Value.Body)
		jsonDecoded := serialize(decoded)
		if !bytes.Equal(jsonPacket, jsonDecoded) {
			t.Errorf("%s: TNSData.Read mismatch:[\n%s\n]", tag, interleave(jsonPacket, jsonDecoded))
		}
		if len(reader.Data) > 0 {
			t.Errorf("%s: TNSData.Read: %d bytes left over", tag, len(reader.Data))
		}
	}
}
