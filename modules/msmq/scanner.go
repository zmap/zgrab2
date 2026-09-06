// Package msmq provides a zgrab2 module that scans for Microsoft Message
// Queuing (MSMQ).
// Default port: 1801 (TCP), Microsoft's documented default port for the
// MS-MQQB queue-manager-to-queue-manager protocol.
//
// To keep traffic minimal while remaining accurate, this module performs
// exactly one exchange: it sends an MS-MQQB EstablishConnection Packet (the
// session-initiation request two MSMQ queue managers exchange) and parses
// the EstablishConnection Packet sent back in response. Receiving either an
// accepted or a refused response is a positive, unambiguous identification
// of an MS-MQQB listener -- a refusal still proves the target speaks the
// protocol, it just declined our request (we deliberately omit the queue
// manager GUID, since a scanner has no way to know it in advance).
//
// Note MSMQ is also reachable via RPC through the endpoint mapper (see the
// msrpc module, default port 135) for its separate client/management
// protocols (MS-MQMP/MS-MQMR); this module targets the distinct raw-TCP
// MS-MQQB listener on port 1801.
package msmq

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the msmq scan module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
}

// Results is the output of the msmq scan module.
type Results struct {
	// Accepted is true if the acceptor's EstablishConnection response did
	// not have the CS (connection refused) flag set.
	Accepted bool `json:"accepted"`
	// ClientGuid/ServerGuid are the queue manager GUIDs echoed back by the
	// acceptor in its EstablishConnectionHeader.
	ClientGuid string `json:"client_guid,omitempty"`
	ServerGuid string `json:"server_guid,omitempty"`
	// TimeStamp is the initiator's timestamp echoed back by the acceptor.
	TimeStamp uint32 `json:"time_stamp"`
	// OperatingSystem is the raw 2-byte EstablishConnectionHeader.OperatingSystem
	// value returned by the acceptor. The high byte is always 0x10 (reserved).
	// The low byte carries OS-type flags defined in [MS-MQQB] 2.2.3.1.
	OperatingSystem uint16 `json:"operating_system,omitempty"`
	// IsSessionMode is true when the SE bit (bit 7 of the low byte of
	// OperatingSystem) is set in the acceptor's response, indicating the
	// acceptor is operating in session/ping mode (no separate Ping Request
	// will follow).
	IsSessionMode bool `json:"is_session_mode,omitempty"`
	// PaddingMatchesServerPattern is true if the 512-byte
	// EstablishConnectionHeader.Padding field was filled entirely with
	// 0x5A, as MS-MQQB mandates for a response from a genuine acceptor --
	// an additional signal that this is a real MS-MQQB implementation.
	PaddingMatchesServerPattern bool `json:"padding_matches_server_pattern"`
	// Raw is the hex-encoded response packet, included when --verbose is set.
	Raw string `json:"raw,omitempty"`
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// NewModule returns a new msmq module.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"msmq",
		"Probe for Microsoft Message Queuing (MSMQ) queue managers",
		"Send an MS-MQQB EstablishConnection request and parse the EstablishConnection reply, identifying MSMQ queue-manager-to-queue-manager (Binary Reliable Messaging Protocol) listeners with a single request/response exchange",
		1801,
	)
}

// Init initializes the Scanner.
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

// Scan connects to the target (default port 1801), sends a single MS-MQQB
// EstablishConnection request, and parses the EstablishConnection reply.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not dial target %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	// A zero ClientGuid/ServerGuid and a zero TimeStamp are all that's
	// needed: ServerGuid == 0 is the documented "direct format name" request
	// form, since a scanner has no way to know the target's real queue
	// manager GUID up front.
	var clientGUID, serverGUID [16]byte
	req := buildEstablishConnection(clientGUID, serverGUID, 0)
	if _, err = conn.Write(req); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not send EstablishConnection request to %s: %w", target.String(), err)
	}

	resp := make([]byte, establishConnectionPacketLen)
	if _, err = io.ReadFull(conn, resp); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not read EstablishConnection reply from %s: %w", target.String(), err)
	}

	parsed, err := parseEstablishConnection(resp)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("reply from %s was not a valid MS-MQQB EstablishConnection packet: %w", target.String(), err)
	}

	results := &Results{
		Accepted:                    !parsed.Refused,
		ClientGuid:                  formatGUID(parsed.ClientGUID),
		ServerGuid:                  formatGUID(parsed.ServerGUID),
		TimeStamp:                   parsed.TimeStamp,
		OperatingSystem:             parsed.OperatingSystem,
		IsSessionMode:               parsed.OperatingSystem&0x0080 != 0,
		PaddingMatchesServerPattern: parsed.PaddingMatchesResponse,
	}
	if scanner.config.Verbose {
		results.Raw = hex.EncodeToString(resp)
	}

	// Both an accepted and a refused EstablishConnection response positively
	// identify an MS-MQQB listener -- a refusal merely means our (necessarily
	// GUID-less) request was declined.
	return zgrab2.SCAN_SUCCESS, results, nil
}
