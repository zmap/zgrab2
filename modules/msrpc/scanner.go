// Package msrpc provides a zgrab2 module that scans for Microsoft RPC
// (MSRPC / DCE-RPC) services.
// Default port: 135 (TCP), the well-known RPC Endpoint Mapper port on
// Windows.
//
// Many Windows-based OT/ICS assets -- engineering workstations, HMIs,
// historian servers, and OPC Classic (DA/AE/HDA) servers, which are built on
// DCOM -- expose this port. Identifying it is a useful, low-noise way to spot
// Windows hosts embedded in an OT network.
//
// To keep traffic minimal while remaining accurate, this module performs
// exactly one DCE/RPC exchange: it sends a Bind PDU proposing the RPC
// Endpoint Mapper interface (by default) with the NDR transfer syntax, and
// parses the resulting bind_ack or bind_nak. Receiving either is a positive,
// unambiguous identification of a DCE/RPC listener -- bind_nak still proves
// the target speaks the protocol, it just declined our specific interface.
// No further calls (e.g. ept_map lookups) are made.
package msrpc

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the msrpc scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`

	// InterfaceUUID/Major/Minor identify the abstract syntax (RPC interface)
	// to Bind to. The default is the RPC Endpoint Mapper interface, which is
	// always present on a genuine Windows RPC listener bound to port 135.
	InterfaceUUID         string `long:"interface-uuid" description:"Interface UUID to propose in the Bind request" default:"e1af8308-5d1f-11c9-91a4-08002b14a0fa"`
	InterfaceVersionMajor uint16 `long:"interface-version-major" description:"Major version of the interface to propose" default:"3"`
	InterfaceVersionMinor uint16 `long:"interface-version-minor" description:"Minor version of the interface to propose" default:"0"`

	// CallID and MaxFrag are exposed for completeness/testing; the defaults
	// match common Windows RPC client behavior and rarely need changing.
	CallID  uint32 `long:"call-id" description:"call_id to use in the Bind request" default:"1"`
	MaxFrag uint16 `long:"max-frag" description:"max_xmit_frag/max_recv_frag to advertise in the Bind request" default:"4280"`
}

// Validate checks that the flags are valid.
func (flags Flags) Validate(_ []string) error {
	if _, err := parseUUID(flags.InterfaceUUID); err != nil {
		return fmt.Errorf("invalid --interface-uuid: %w", err)
	}
	return nil
}

// Results is the output of the msrpc scan module.
type Results struct {
	// PDUType is the type of PDU the server returned: "bind_ack" or
	// "bind_nak".
	PDUType string `json:"pdu_type"`
	// Accepted is true if the server's bind_ack accepted our proposed
	// interface and transfer syntax.
	Accepted bool `json:"accepted"`

	// InterfaceUUID/InterfaceVersion identify the interface we proposed in
	// the Bind request.
	InterfaceUUID    string `json:"interface_uuid"`
	InterfaceVersion string `json:"interface_version"`
	// TransferSyntax identifies the transfer syntax the server accepted,
	// only set when Accepted is true.
	TransferSyntax string `json:"transfer_syntax,omitempty"`

	// ResultCode/ResultDescription describe the presentation-context result
	// carried in a bind_ack (e.g. "acceptance", "provider_rejection").
	ResultCode        *uint16 `json:"result_code,omitempty"`
	ResultDescription string  `json:"result_description,omitempty"`
	// RejectReasonCode/RejectReasonDescription explain why a bind_nak, or a
	// bind_ack with a non-acceptance result, was returned.
	RejectReasonCode        *uint16 `json:"reject_reason_code,omitempty"`
	RejectReasonDescription string  `json:"reject_reason_description,omitempty"`

	// MaxXmitFrag/MaxRecvFrag/AssocGroupID/SecondaryAddress are echoed by the
	// server in a bind_ack.
	MaxXmitFrag      uint16 `json:"max_xmit_frag,omitempty"`
	MaxRecvFrag      uint16 `json:"max_recv_frag,omitempty"`
	AssocGroupID     uint32 `json:"assoc_group_id,omitempty"`
	SecondaryAddress string `json:"secondary_address,omitempty"`

	// CallID is the call identifier echoed back by the server.
	CallID uint32 `json:"call_id"`

	// Raw is the hex-encoded response PDU, included when --verbose is set.
	Raw string `json:"raw,omitempty"`
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// NewModule returns a new msrpc module.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"msrpc",
		"Probe for Microsoft RPC (MSRPC/DCE-RPC) endpoint mapper services",
		"Send a single DCE/RPC Bind request and parse the bind_ack/bind_nak reply, identifying Windows RPC listeners (e.g. OT engineering workstations, HMIs, OPC Classic servers) with minimal traffic",
		135,
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

// readPDU reads a single DCE/RPC PDU from conn: the fixed 16-byte common
// header, then exactly frag_length-16 more bytes, as declared by the header.
func readPDU(conn io.Reader) ([]byte, *commonHeader, error) {
	header := make([]byte, commonHeaderLen)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil, fmt.Errorf("could not read DCE/RPC header: %w", err)
	}
	hdr, err := parseCommonHeader(header)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid DCE/RPC header: %w", err)
	}
	full := make([]byte, hdr.FragLength)
	copy(full, header)
	if rest := full[commonHeaderLen:]; len(rest) > 0 {
		if _, err := io.ReadFull(conn, rest); err != nil {
			return nil, nil, fmt.Errorf("could not read DCE/RPC body: %w", err)
		}
	}
	return full, hdr, nil
}

// Scan connects to the target (default port 135), sends a single DCE/RPC
// Bind request for the configured interface, and parses the bind_ack or
// bind_nak reply.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not dial target %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	abstractUUID, err := parseUUID(scanner.config.InterfaceUUID)
	if err != nil {
		// Already validated in Flags.Validate; this should be unreachable.
		return zgrab2.SCAN_INVALID_INPUTS, nil, err
	}

	req := buildBind(scanner.config.CallID, scanner.config.MaxFrag, abstractUUID, scanner.config.InterfaceVersionMajor, scanner.config.InterfaceVersionMinor)
	if _, err = conn.Write(req); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not send Bind request to %s: %w", target.String(), err)
	}

	full, hdr, err := readPDU(conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not read Bind reply from %s: %w", target.String(), err)
	}

	results := &Results{
		CallID:           hdr.CallID,
		InterfaceUUID:    scanner.config.InterfaceUUID,
		InterfaceVersion: fmt.Sprintf("%d.%d", scanner.config.InterfaceVersionMajor, scanner.config.InterfaceVersionMinor),
	}
	if scanner.config.Verbose {
		results.Raw = hex.EncodeToString(full)
	}

	switch hdr.PType {
	case ptypeBindAck:
		results.PDUType = "bind_ack"
		ack, err := parseBindAck(full)
		if err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("malformed bind_ack from %s: %w", target.String(), err)
		}
		results.MaxXmitFrag = ack.MaxXmitFrag
		results.MaxRecvFrag = ack.MaxRecvFrag
		results.AssocGroupID = ack.AssocGroupID
		results.SecondaryAddress = ack.SecondaryAddress

		resultCode := ack.ResultCode
		results.ResultCode = &resultCode
		results.ResultDescription = resultCodeName(ack.ResultCode)

		if ack.ResultCode == resultAcceptance {
			results.Accepted = true
			results.TransferSyntax = fmt.Sprintf("%s v%d.%d", ack.TransferSyntaxUUID, ack.TransferSyntaxVerMajor, ack.TransferSyntaxVerMinor)
		} else {
			rejectReason := ack.RejectReason
			results.RejectReasonCode = &rejectReason
			results.RejectReasonDescription = rejectReasonName(ack.RejectReason)
		}
	case ptypeBindNak:
		results.PDUType = "bind_nak"
		nak, err := parseBindNak(full)
		if err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("malformed bind_nak from %s: %w", target.String(), err)
		}
		rejectReason := nak.RejectReason
		results.RejectReasonCode = &rejectReason
		results.RejectReasonDescription = rejectReasonName(nak.RejectReason)
	default:
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("unexpected DCE/RPC PDU type %d from %s", hdr.PType, target.String())
	}

	// Both bind_ack and bind_nak positively identify a DCE/RPC listener --
	// bind_nak merely means our proposed interface/transfer syntax was
	// declined.
	return zgrab2.SCAN_SUCCESS, results, nil
}
