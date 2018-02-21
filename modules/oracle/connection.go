package oracle

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/zmap/zgrab2"
)

const (
	logIndexConnect     int = 0
	logIndexAccept          = 1
	logIndexNSNRequest      = 2
	logIndexNSNResponse     = 3
)

type HandshakeLog struct {
	RawAccept            []byte             `json:"raw_accept,omitempty" zgrab:"debug"`
	AcceptVersion        uint16             `json:"accept_version"`
	GlobalServiceOptions map[string]bool    `json:"global_service_options,omitempty"`
	ConnectFlags         [2]map[string]bool `json:"connect_flags,omitempty"`

	DidResend bool `json:"did_resend"`

	RawNSN             []byte            `json:"raw_nsn,omitempty" zgrab:"debug"`
	NSNVersion         string            `json:"nsn_version,omitempty"`
	NSNServiceVersions map[string]string `json:"nsn_service_versions,omitempty"`
}

type PacketLogEntry struct {
	Outgoing bool
	Data     []byte
}

type loggedReader struct {
	reader io.Reader
	data   []byte
}

func logReader(reader io.Reader) *loggedReader {
	return &loggedReader{reader: reader}
}

func (reader *loggedReader) Read(data []byte) (int, error) {
	n, err := reader.reader.Read(data)
	if err != nil {
		reader.data = append(reader.data, data[0:n]...)
	}
	return n, err
}

type Connection struct {
	conn      net.Conn
	target    *zgrab2.ScanTarget
	scanner   *Scanner
	resent    bool
	packetLog []PacketLogEntry
	reader    *loggedReader
}

func (conn *Connection) getLastPacket(outgoing bool) []byte {
	for i := range conn.packetLog {
		r := len(conn.packetLog) - i - 1
		v := conn.packetLog[r]
		if v.Outgoing == outgoing {
			return v.Data
		}
	}
	return nil
}

func (conn *Connection) send(data []byte) error {
	conn.appendLogEntry(true, data)
	rest := data
	n := 0
	for n < len(rest) {
		fmt.Println("n=", n, "rest=", len(rest))
		n, err := conn.conn.Write(rest)
		if err != nil {
			return err
		}
		rest = rest[n:]
	}
	return nil
}

func (conn *Connection) appendLogEntry(outgoing bool, data []byte) {
	conn.packetLog = append(conn.packetLog, PacketLogEntry{
		Outgoing: outgoing,
		Data:     data,
	})
}

func (conn *Connection) readPacket() (*TNSPacket, error) {
	wrapped := logReader(conn.conn)
	ret, err := ReadTNSPacket(wrapped)
	conn.appendLogEntry(false, wrapped.data)
	return ret, err
}

func (conn *Connection) SendPacket(packet TNSPacketBody) (TNSPacketBody, error) {
	toSend := (&TNSPacket{Body: packet}).Encode()

	if err := conn.send(toSend); err != nil {
		return nil, err
	}

	response, err := conn.readPacket()
	if err != nil {
		return nil, err
	}

	if response.Body.GetType() == PacketTypeResend {
		conn.resent = true
		// Only re-send once.
		if err = conn.send(toSend); err != nil {
			return nil, err
		}
		response, err = conn.readPacket()
		if err != nil {
			return nil, err
		}
	}
	return response.Body, nil
}

func u16Flag(v string) uint16 {
	ret, err := strconv.ParseUint(v, 0, 16)

	if err != nil {
		panic(err)
	}
	return uint16(ret)
}

/*
func dump(tag string, val interface{}) {
	j, err := json.MarshalIndent(val, "  ", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(tag + "=[[" + string(j) + "]]")

}
*/
func (conn *Connection) Connect(connectionString string) (*HandshakeLog, error) {
	result := HandshakeLog{}
	if len(connectionString) > 0x7fff {
		return nil, ErrInvalidInput
	}
	// TODO: Variable fields in the connection string (e.g. host?)
	connectPacket := &TNSConnect{
		Version:              conn.scanner.config.Version,
		MinVersion:           conn.scanner.config.MinVersion,
		GlobalServiceOptions: ServiceOptions(u16Flag(conn.scanner.config.GlobalServiceOptions)),
		SDU:                  u16Flag(conn.scanner.config.SDU),
		TDU:                  u16Flag(conn.scanner.config.TDU),
		ProtocolCharacteristics: NTProtocolCharacteristics(u16Flag(conn.scanner.config.ProtocolCharacterisics)),
		MaxBeforeAck:            0,
		ByteOrder:               DefaultByteOrder,
		DataLength:              uint16(len(connectionString)),
		DataOffset:              0x003A,
		MaxResponseSize:         0x00000800,
		ConnectFlags0:           ConnectFlags(u16Flag(conn.scanner.config.ConnectFlags) & 0xff),
		ConnectFlags1:           ConnectFlags(u16Flag(conn.scanner.config.ConnectFlags) >> 8),
		CrossFacility0:          0,
		CrossFacility1:          0,
		ConnectionID0:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
		ConnectionID1:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
		Unknown3A:               []byte{},
		ConnectionString:        connectionString,
	}
	response, err := conn.SendPacket(connectPacket)
	if err != nil {
		return nil, err
	}
	if conn.resent {
		result.DidResend = true
	}
	result.RawAccept = conn.getLastPacket(false)

	accept, ok := response.(*TNSAccept)
	if !ok {
		return &result, ErrUnexpectedResponse
	}
	// TODO: Unclear what these do. Taken from my client.
	result.AcceptVersion = accept.Version
	result.GlobalServiceOptions = accept.GlobalServiceOptions.Set()
	result.ConnectFlags = [2]map[string]bool{
		accept.ConnectFlags0.Set(),
		accept.ConnectFlags1.Set(),
	}
	// uint32 PID + uint32 ??
	supervisorBytes0 := []byte{0x00, 0x00, 0x04, 0xec, 0x19, 0x2c, 0x7b, 0x4c}

	supervisorBytes1 := []byte{
		0xde, 0xad, 0xbe, 0xef,
		0x00, 0x03, // Array type?
		0x00, 0x00, 0x00, 0x04, // Array length?
		0x00, 0x04, // Drivers?
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x02,
	}

	authUB2 := uint16(0xe0e1)
	authStatus := uint16(0xfcff)
	authUB1 := uint8(1)

	// Windows NTS authentication
	authString := "NTS"

	// Supported encryption algorithms?
	encryptionBytes := []byte{0x00, 0x11, 0x06, 0x10, 0x0c, 0x0f, 0x0a, 0x0b, 0x08, 0x02, 0x01, 0x03}

	// Drivers?
	dataIntegrityBytes := []byte{0x00, 0x03, 0x01}

	nsnRequest := &TNSData{
		DataFlags: 0,
		Data: (&TNSDataNSN{
			Version: EncodeReleaseVersion(conn.scanner.config.ReleaseVersion),
			Options: NSNOptions(0),
			Services: []NSNService{
				NSNService{
					Type: NSNServiceSupervisor,
					Values: []NSNValue{
						*NSNValueVersion(conn.scanner.config.ReleaseVersion),
						*NSNValueBytes(supervisorBytes0),
						*NSNValueBytes(supervisorBytes1),
					},
					Marker: 0,
				},
				NSNService{
					Type: NSNServiceAuthentication,
					Values: []NSNValue{
						*NSNValueVersion(conn.scanner.config.ReleaseVersion),
						*NSNValueUB2(authUB2),
						*NSNValueStatus(authStatus),
						*NSNValueUB1(authUB1),
						*NSNValueString(authString),
					},
					Marker: 0,
				},
				NSNService{
					Type: NSNServiceEncryption,
					Values: []NSNValue{
						*NSNValueVersion(conn.scanner.config.ReleaseVersion),
						*NSNValueBytes(encryptionBytes),
					},
					Marker: 0,
				},
				NSNService{
					Type: NSNServiceDataIntegrity,
					Values: []NSNValue{
						*NSNValueVersion(conn.scanner.config.ReleaseVersion),
						*NSNValueBytes(dataIntegrityBytes),
					},
				},
			},
		}).Encode(),
	}

	response, err = conn.SendPacket(nsnRequest)
	if err != nil {
		return &result, err
	}

	result.RawNSN = conn.getLastPacket(false)

	wrappedNSNResponse, ok := response.(*TNSData)
	if !ok {
		return &result, ErrUnexpectedResponse
	}

	if wrappedNSNResponse.GetID() != DataIDNSN {
		return &result, ErrUnexpectedResponse
	}

	nsnResponse, err := DecodeTNSDataNSN(wrappedNSNResponse.Data)
	if err != nil {
		return &result, err
	}
	result.NSNServiceVersions = make(map[string]string)
	for _, svc := range nsnResponse.Services {
		if !svc.Type.IsUnknown() {
			for _, sub := range svc.Values {
				if sub.Type == NSNValueTypeVersion {
					result.NSNServiceVersions[svc.Type.String()] = sub.String()
					break
				}
			}
		}
	}

	return &result, nil
}
