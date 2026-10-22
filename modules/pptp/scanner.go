// Package pptp contains the zgrab2 Module implementation for PPTP.
package pptp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/zmap/zgrab2"
)

// ScanResults is the output of the scan.
type ScanResults struct {
	// Banner is the Start-Control-Connection-Request sent to the server.
	Banner string `json:"banner,omitempty"`

	// ControlMessage is the received PPTP control message.
	ControlMessage string `json:"control_message,omitempty"`

	*SCCRP
}

// SCCRP contains the fields of a Start-Control-Connection-Reply.
type SCCRP struct {
	ProtocolVersion   uint16 `json:"protocol_version"`
	ResultCode        uint8  `json:"result_code"`
	ErrorCode         uint8  `json:"error_code"`
	FramingCapability uint32 `json:"framing_capability"`
	BearerCapability  uint32 `json:"bearer_capability"`
	MaximumChannels   uint16 `json:"maximum_channels"`
	FirmwareRevision  uint16 `json:"firmware_revision"`
	Hostname          string `json:"hostname"`
	Vendor            string `json:"vendor"`
}

// Flags are the PPTP-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("pptp", "Point-to-Point Tunneling Protocol (PPTP)", "Scan for PPTP", 1723)
}

// Scanner implements the zgrab2.Scanner interface, and holds the state
// for a single scan.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// Init initializes the Scanner instance with the flags from the command line.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// PPTP Start-Control-Connection-Request message constants
const (
	PPTP_MAGIC_COOKIE       = 0x1A2B3C4D // PPTP Magic Cookie in bytes, see RFC 2637 section 1.4
	PPTP_CONTROL_MESSAGE    = 1
	PPTP_START_CONN_REQUEST = 1
	PPTP_START_CONN_REPLY   = 2
	PPTP_PROTOCOL_VERSION   = 0x0100
	pptpSCCRLength          = 156
)

// Connection holds the state for a single connection to the PPTP server.
type Connection struct {
	config  *Flags
	results ScanResults
	conn    net.Conn
}

// Create the Start-Control-Connection-Request message
func createSCCRMessage() []byte {
	message := make([]byte, pptpSCCRLength)
	binary.BigEndian.PutUint16(message[0:2], pptpSCCRLength)
	binary.BigEndian.PutUint16(message[2:4], PPTP_CONTROL_MESSAGE)     // PPTP Message Type
	binary.BigEndian.PutUint32(message[4:8], PPTP_MAGIC_COOKIE)        // Magic Cookie
	binary.BigEndian.PutUint16(message[8:10], PPTP_START_CONN_REQUEST) // Control Message Type
	binary.BigEndian.PutUint16(message[12:14], PPTP_PROTOCOL_VERSION)
	copy(message[28:92], "ZGRAB2-SCANNER")
	copy(message[92:156], "ZGRAB2")
	return message
}

// readResponse reads one complete, length-prefixed PPTP control message.
func (pptp *Connection) readResponse() ([]byte, error) {
	if err := pptp.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, fmt.Errorf("could not set read deadline: %w", err)
	}
	response := make([]byte, pptpSCCRLength)
	if _, err := io.ReadFull(pptp.conn, response[:2]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("incomplete PPTP response length: %w", err))
		}
		return nil, fmt.Errorf("could not read PPTP response length: %w", err)
	}
	if length := binary.BigEndian.Uint16(response[:2]); length != pptpSCCRLength {
		return response[:2], zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("invalid PPTP SCCRP length %d", length))
	}
	if _, err := io.ReadFull(pptp.conn, response[2:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("incomplete PPTP response body: %w", err))
		}
		return nil, fmt.Errorf("could not read PPTP response body: %w", err)
	}
	return response, nil
}

func parseSCCRP(response []byte) (*SCCRP, error) {
	if len(response) != pptpSCCRLength || binary.BigEndian.Uint16(response[:2]) != pptpSCCRLength {
		return nil, fmt.Errorf("invalid PPTP SCCRP length %d", len(response))
	}
	if binary.BigEndian.Uint16(response[2:4]) != PPTP_CONTROL_MESSAGE ||
		binary.BigEndian.Uint32(response[4:8]) != PPTP_MAGIC_COOKIE ||
		binary.BigEndian.Uint16(response[8:10]) != PPTP_START_CONN_REPLY {
		return nil, errors.New("invalid PPTP SCCRP header")
	}
	return &SCCRP{
		ProtocolVersion:   binary.BigEndian.Uint16(response[12:14]),
		ResultCode:        response[14],
		ErrorCode:         response[15],
		FramingCapability: binary.BigEndian.Uint32(response[16:20]),
		BearerCapability:  binary.BigEndian.Uint32(response[20:24]),
		MaximumChannels:   binary.BigEndian.Uint16(response[24:26]),
		FirmwareRevision:  binary.BigEndian.Uint16(response[26:28]),
		Hostname:          string(bytes.TrimRight(response[28:92], "\x00")),
		Vendor:            string(bytes.TrimRight(response[92:156], "\x00")),
	}, nil
}

// Scan performs the configured scan on the PPTP server
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	var err error
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error opening connection to target %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	results := ScanResults{}

	pptp := Connection{conn: conn, config: scanner.config, results: results}

	// Send Start-Control-Connection-Request message
	request := createSCCRMessage()
	_, err = io.Copy(pptp.conn, bytes.NewReader(request))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &pptp.results, fmt.Errorf("error sending PPTP SCCR message to target %s: %w", target.String(), err)
	}

	// Read the response
	respBytes, err := pptp.readResponse()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &pptp.results, fmt.Errorf("error reading PPTP response from target %s: %w", target.String(), err)
	}

	// Preserve the existing raw fields for clients that use them.
	pptp.results.Banner = string(request)
	pptp.results.ControlMessage = string(respBytes)

	pptp.results.SCCRP, err = parseSCCRP(respBytes)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, &pptp.results, fmt.Errorf("invalid PPTP response from target %s: %w", target.String(), err)
	}
	if pptp.results.ResultCode != 1 {
		return zgrab2.SCAN_PROTOCOL_ERROR, &pptp.results, fmt.Errorf("PPTP control connection rejected by target %s (result code %d, error code %d)", target.String(), pptp.results.ResultCode, pptp.results.ErrorCode)
	}

	return zgrab2.SCAN_SUCCESS, &pptp.results, nil
}
