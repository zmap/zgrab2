package oracle

import (
	"net"

	"github.com/zmap/zgrab2"
)

type Connection struct {
	conn    net.Conn
	target  *zgrab2.ScanTarget
	scanner *Scanner
}

/*
type Encodable interface {
	Encode() []byte
}

func (conn *Connection) SendPacket(packet Encodable) (interface{}, error) {
	for encoded := packet.Encode(); n, err := conn.conn.Write(encoded); n < len(encoded) {
		if err != nil {
			return nil, err
		}
		encoded = encoded[n:]
	}
}

func (conn *Connection) Connect(connectionString string) {
		ConnectValue: &TNSConnect{
			TNSHeader:            TNSHeader{Length: 0x00ca, PacketChecksum: 0, Type: PacketTypeConnect, Flags: 0, HeaderChecksum: 0},
			Version:              0x013a,
			MinVersion:           0x012c,
			GlobalServiceOptions: SOHeaderChecksum | SOFullDuplex | SOUnknown0040 | SOUnknown0001, // (0x0c41)
			SDU:                  0x2000,
			TDU:                  0xffff,
			ProtocolCharacteristics: NTPCConfirmedRelease | NTPCTDUBasedIO | NTPCSpawnerRunning | NTPCDataTest | NTPCCallbackIO | NTPCAsyncIO | NTPCPacketIO | NTPCGenerateSIGURG, // 0x7F08
			MaxBeforeAck:            0,
			ByteOrder:               DefaultByteOrder,
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
}
*/
