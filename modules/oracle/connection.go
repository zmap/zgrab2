package oracle

import (
	"net"
	"strconv"

	"github.com/zmap/zgrab2"
)

// HandshakeLog gives the results of the initial connection handshake in a form
// suitable for zgrab2 output.
type HandshakeLog struct {
	// AcceptVersion is the protocol version value from the Accept packet.
	AcceptVersion uint16 `json:"accept_version"`

	// GlobalServiceOptions is the set of GlobalServiceOptions flags that the
	// server returns in the Accept packet.
	GlobalServiceOptions map[string]bool `json:"global_service_options,omitempty"`

	// ConnectFlags0 is the first set of ConnectFlags values that the server
	// returns in the Accept packet for the first.
	ConnectFlags0 map[string]bool `json:"connect_flags0,omitempty"`

	// ConnectFlags1 is the second set of ConnectFlags values that the server
	// returns in the Accept packet for the first.
	ConnectFlags1 map[string]bool `json:"connect_flags1,omitempty"`

	// DidResend is true if the server sent a Resend packet in response to the
	// client's first Connect packet.
	DidResend bool `json:"did_resend"`

	// RedirectTargetRaw is the connect descriptor returned by the server in the
	// Redirect packet, if one is sent. Otherwise it is empty/omitted.
	RedirectTargetRaw string `json:"redirect_target_raw,omitempty"`

	// RedirectTarget is the parsed connect descriptor returned by the server in
	// the Redirect packet, if one is sent. Otherwise it is empty/omitted.
	RedirectTarget Descriptor `json:"redirect_target,omitempty"`

	// RefuseErrorRaw is the Data from the Refuse packet returned by the server;
	// it is empty if the server does not return a Refuse packet.
	RefuseErrorRaw string `json:"refuse_error_raw,omitempty"`

	// RefuseError is the parsed descriptor returned by the server in the Refuse
	// packet; it is empty if the server does not return a Refuse packet.
	RefuseError Descriptor `json:"refuse_error,omitempty"`

	// RefuseReasonApp is the "AppReason" returned by the server in a Refused
	// response packet.
	RefuseReasonApp string `json:"refuse_reason_app,omitempty"`

	// RefuseReasonSys is the "SysReason" returned by the server in a Refused
	// response packet.
	RefuseReasonSys string `json:"refuse_reason_sys,omitempty"`

	// RefuseVersion is the parsed DESCRIPTION.VSNNUM field from the RefuseError
	// string returned by the server in the Refuse packet, in dotted-decimal
	// format.
	RefuseVersion string `json:"refuse_version,omitempty"`

	// DidResend is set to true if the server sent a Resend packet after the
	// first Connect packet.

	// NSNVersion is the ReleaseVersion string (in dotted decimal format) in the
	// root of the Native Service Negotiation packet.
	NSNVersion string `json:"nsn_version,omitempty"`

	// NSNServiceVersions is a map from the Native Service Negotiation service
	// name to the ReleaseVersion in that service packet.
	NSNServiceVersions map[string]string `json:"nsn_service_versions,omitempty"`
}

// Connection holds the state for a scan connection to the Oracle server.
type Connection struct {
	conn      net.Conn
	target    *zgrab2.ScanTarget
	scanner   *Scanner
	resent    bool
	redirect  string
	tnsDriver *TNSDriver
}

// send ensures everything gets written
func (conn *Connection) send(data []byte) error {
	rest := data
	n := 0
	for n < len(rest) {
		n, err := conn.conn.Write(rest)
		if err != nil {
			return err
		}
		rest = rest[n:]
	}
	return nil
}

// readPacket tries to read/parse a packet from the connection.
func (conn *Connection) readPacket() (*TNSPacket, error) {
	return conn.tnsDriver.ReadTNSPacket(conn.conn)
}

// SendPacket sends the given packet body to the server (prefixing the
// appropriate header -- with flags == 0), and read / parse the response.
// Automatically handles Resend responses; the caller is responsible for
// handling other exceptional cases.
func (conn *Connection) SendPacket(packet TNSPacketBody) (TNSPacketBody, error) {
	toSend, err := conn.tnsDriver.EncodePacket(&TNSPacket{Body: packet})
	if err != nil {
		return nil, err
	}

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

// Handle numeric args in any radix.
func u16Flag(v string) uint16 {
	ret, err := strconv.ParseUint(v, 0, 16)

	if err != nil {
		panic(err)
	}
	return uint16(ret)
}

// Connect to the server and do a handshake with the given config.
func (conn *Connection) Connect(connectDescriptor string) (*HandshakeLog, error) {
	result := HandshakeLog{}
	extraData := []byte{}
	if len(connectDescriptor)+len(extraData)+0x3A > 0x7fff {
		return nil, ErrInvalidInput
	}

	// TODO: Variable fields in the connect descriptor (e.g. host?)
	connectPacket := &TNSConnect{
		Version:                 conn.scanner.config.Version,
		MinVersion:              conn.scanner.config.MinVersion,
		GlobalServiceOptions:    ServiceOptions(u16Flag(conn.scanner.config.GlobalServiceOptions)),
		SDU:                     u16Flag(conn.scanner.config.SDU),
		TDU:                     u16Flag(conn.scanner.config.TDU),
		ProtocolCharacteristics: NTProtocolCharacteristics(u16Flag(conn.scanner.config.ProtocolCharacterisics)),
		MaxBeforeAck:            0,
		ByteOrder:               defaultByteOrder,
		DataLength:              uint16(len(connectDescriptor)),
		DataOffset:              uint16(0x003A + len(extraData)),
		MaxResponseSize:         0x00000800,
		ConnectFlags0:           ConnectFlags(u16Flag(conn.scanner.config.ConnectFlags) & 0xff),
		ConnectFlags1:           ConnectFlags(u16Flag(conn.scanner.config.ConnectFlags) >> 8),
		CrossFacility0:          0,
		CrossFacility1:          0,
		ConnectionID0:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
		ConnectionID1:           [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
		Unknown3A:               extraData,
		ConnectDescriptor:       connectDescriptor,
	}
	response, err := conn.SendPacket(connectPacket)

	if err != nil {
		return nil, err
	}
	if conn.resent {
		result.DidResend = true
	}
	var accept *TNSAccept
	switch resp := response.(type) {
	case *TNSAccept:
		accept = resp
	case *TNSRedirect:
		result.RedirectTargetRaw = string(resp.Data)
		if parsed, err := DecodeDescriptor(result.RedirectTargetRaw); err != nil {
			result.RedirectTarget = parsed
		}
		// TODO: Follow redirects?
		return &result, nil
	case *TNSRefuse:
		result.RefuseErrorRaw = string(resp.Data)
		result.RefuseReasonApp = resp.AppReason.String()
		result.RefuseReasonSys = resp.SysReason.String()
		if desc, err := DecodeDescriptor(result.RefuseErrorRaw); err == nil {
			result.RefuseError = desc
			if versions := desc.GetValues("DESCRIPTION.VSNNUM"); len(versions) > 0 {
				// If there are multiple VSNNUMs, we only care about the first.
				decVersion := versions[0]
				if intVersion, err := strconv.ParseUint(decVersion, 10, 32); err == nil {
					result.RefuseVersion = ReleaseVersion(intVersion).String()
				}
			}
		}
		return &result, nil
	default:
		return &result, ErrUnexpectedResponse
	}

	// TODO: Unclear what all of these values these do. Defaults taken from the
	// values sent by the Oracle SQLPlus 11.2 client.
	result.AcceptVersion = accept.Version
	result.GlobalServiceOptions = accept.GlobalServiceOptions.Set()
	result.ConnectFlags0 = accept.ConnectFlags0.Set()
	result.ConnectFlags1 = accept.ConnectFlags1.Set()

	// uint32 PID + uint32 ??
	// In real clients, seems to be a small u32 followed by some kind of u32
	// counter/timestamp.
	supervisorBytes0 := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

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

	encoded, err := (&TNSDataNSN{
		ID:      DataIDNSN,
		Version: encodeReleaseVersion(conn.scanner.config.ReleaseVersion),
		Options: NSNOptions(0),
		Services: []NSNService{
			{
				Type: NSNServiceSupervisor,
				Values: []NSNValue{
					*NSNValueVersion(conn.scanner.config.ReleaseVersion),
					*NSNValueBytes(supervisorBytes0),
					*NSNValueBytes(supervisorBytes1),
				},
				Marker: 0,
			},
			{
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
			{
				Type: NSNServiceEncryption,
				Values: []NSNValue{
					*NSNValueVersion(conn.scanner.config.ReleaseVersion),
					*NSNValueBytes(encryptionBytes),
				},
				Marker: 0,
			},
			{
				Type: NSNServiceDataIntegrity,
				Values: []NSNValue{
					*NSNValueVersion(conn.scanner.config.ReleaseVersion),
					*NSNValueBytes(dataIntegrityBytes),
				},
			},
		},
	}).Encode()

	if err != nil {
		return &result, err
	}

	nsnRequest := &TNSData{
		DataFlags: 0,
		Data:      encoded,
	}

	response, err = conn.SendPacket(nsnRequest)
	if err != nil {
		return &result, err
	}

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
