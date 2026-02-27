// Package rdp provides a zgrab2 module that scans for Remote Desktop Protocol.
// Default port: TCP 3389
//
// The scanner performs an X.224 Connection Request/Confirm exchange to detect
// any RDP implementation (Microsoft, xrdp, FreeRDP, etc.), then conditionally
// upgrades to TLS and performs NTLM fingerprinting when the server supports
// CredSSP (NLA), which is typical for Microsoft RDP.
package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/ntlm"
)

// Flags holds the command-line configuration for the scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config            *Flags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("rdp", "rdp", module.Description(), 3389, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Probe for Remote Desktop Protocol"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(_ []string) error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      true,
		TLSFlags:                        &f.TLSFlags,
	}
	return nil
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "rdp"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// GetScanMetadata returns any metadata on the scan itself from this module.
func (scanner *Scanner) GetScanMetadata() any {
	return nil
}

// Scan probes for RDP services.
//  1. Connect via plain TCP (L4Dialer).
//  2. Send X.224 Connection Request with CredSSP+TLS negotiation.
//  3. Parse X.224 Connection Confirm to identify the RDP server.
//  4. If CredSSP is selected, upgrade to TLS and perform NTLM fingerprinting.
//  5. If TLS-only is selected, upgrade to TLS and capture the certificate.
//  6. Return the combined result.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found; RDP requires a L4 dialer")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	result := new(RDPResult)

	// --- Step 1: X.224 Connection Request / Confirm ---
	selectedProtocol, negFlags, failureCode, err := x224Negotiate(conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	result.NegotiationFlags = decodeNegotiationFlags(negFlags)

	if failureCode != 0 {
		if name, ok := failureCodeNames[failureCode]; ok {
			result.FailureCode = name
		} else {
			result.FailureCode = fmt.Sprintf("unknown(0x%x)", failureCode)
		}
		// A failure response still confirms this is an RDP server.
		return zgrab2.SCAN_SUCCESS, result, nil
	}

	if name, ok := selectedProtocolNames[selectedProtocol]; ok {
		result.SelectedProtocol = name
	} else {
		result.SelectedProtocol = fmt.Sprintf("unknown(0x%x)", selectedProtocol)
	}

	// --- Step 2: Conditional TLS upgrade ---
	needTLS := selectedProtocol == protocolSSL || selectedProtocol == protocolHybrid || selectedProtocol == protocolHybridEx
	if needTLS {
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found; RDP TLS upgrade requires a TLS wrapper")
		}
		tlsConn, tlsErr := tlsWrapper(ctx, target, conn)
		if tlsErr != nil {
			return zgrab2.TryGetScanStatus(tlsErr), result, fmt.Errorf("TLS upgrade failed: %w", tlsErr)
		}
		result.TLSLog = tlsConn.GetLog()
		conn = tlsConn
	}

	// --- Step 3: Conditional NTLM fingerprinting (CredSSP servers only) ---
	if selectedProtocol == protocolHybrid || selectedProtocol == protocolHybridEx {
		ntlmStatus, ntlmErr := ntlmFingerprint(conn, result)
		if ntlmErr != nil {
			return ntlmStatus, result, ntlmErr
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}

// -----------------------------------------------------------------------
// X.224 Connection Request / Confirm
// -----------------------------------------------------------------------

// buildX224ConnectionRequest builds a TPKT + X.224 CR + cookie + RDP
// Negotiation Request packet. requestedProtocols is a bitmask of
// protocolSSL, protocolHybrid, etc.
func buildX224ConnectionRequest(requestedProtocols uint32) []byte {
	// RDP Negotiation Request (8 bytes)
	var negReq [8]byte
	negReq[0] = typeRDPNegReq // type
	negReq[1] = 0x00          // flags
	binary.LittleEndian.PutUint16(negReq[2:4], 8)
	binary.LittleEndian.PutUint32(negReq[4:8], requestedProtocols)

	// X.224 CR TPDU header: LI, CR|CDT, DST-REF, SRC-REF, CLASS
	// LI = length of everything after LI byte in the X.224 TPDU
	x224Fixed := []byte{
		0x00, // placeholder LI — filled below
		x224TPDUConnectionRequest, // CR + CDT=0
		0x00, 0x00, // DST-REF
		0x00, 0x00, // SRC-REF
		0x00, // Class 0
	}
	x224PayloadLen := len(x224Fixed) - 1 + len(x224Cookie) + len(negReq)
	x224Fixed[0] = byte(x224PayloadLen)

	// TPKT header: version(1) + reserved(1) + length(2 big-endian)
	tpktLen := 4 + 1 + x224PayloadLen // 4-byte TPKT + LI byte + rest
	tpkt := []byte{
		0x03, 0x00,
		byte(tpktLen >> 8), byte(tpktLen),
	}

	var buf bytes.Buffer
	buf.Write(tpkt)
	buf.Write(x224Fixed)
	buf.Write(x224Cookie)
	buf.Write(negReq[:])
	return buf.Bytes()
}

// x224Negotiate sends an X.224 Connection Request and parses the
// Connection Confirm. Returns (selectedProtocol, flags, failureCode, error).
// On negotiation failure responses failureCode is non-zero.
func x224Negotiate(conn net.Conn) (selectedProtocol uint32, flags uint8, failureCode uint32, err error) {
	pkt := buildX224ConnectionRequest(protocolSSL | protocolHybrid)
	if _, err = conn.Write(pkt); err != nil {
		return
	}

	// Read TPKT header (4 bytes)
	tpktBuf := make([]byte, 4)
	if _, err = io.ReadFull(conn, tpktBuf); err != nil {
		return
	}
	if tpktBuf[0] != 0x03 {
		err = fmt.Errorf("invalid TPKT version %d", tpktBuf[0])
		return
	}
	pktLen := int(binary.BigEndian.Uint16(tpktBuf[2:4]))
	if pktLen < 11 || pktLen > 1024 {
		err = fmt.Errorf("unexpected TPKT length %d", pktLen)
		return
	}

	// Read the rest of the packet
	rest := make([]byte, pktLen-4)
	if _, err = io.ReadFull(conn, rest); err != nil {
		return
	}

	// Validate X.224 CC TPDU type (second byte of TPDU, after LI)
	if len(rest) < 7 {
		err = errors.New("X.224 response too short")
		return
	}
	tpduCode := rest[1] & 0xF0
	if tpduCode != x224TPDUConnectionConfirm {
		err = fmt.Errorf("expected X.224 Connection Confirm (0xD0), got 0x%02X", tpduCode)
		return
	}

	// The optional RDP Negotiation Response/Failure starts after the 7-byte
	// X.224 CC fixed header (LI + type + DST-REF + SRC-REF + class).
	negOffset := 7
	if len(rest) < negOffset+8 {
		// No negotiation extension — old-style server using Standard RDP Security.
		selectedProtocol = protocolRDP
		return
	}

	negType := rest[negOffset]
	flags = rest[negOffset+1]

	switch negType {
	case typeRDPNegRsp:
		selectedProtocol = binary.LittleEndian.Uint32(rest[negOffset+4 : negOffset+8])
	case typeRDPNegFailure:
		failureCode = binary.LittleEndian.Uint32(rest[negOffset+4 : negOffset+8])
	default:
		err = fmt.Errorf("unexpected negotiation type 0x%02X", negType)
	}
	return
}

// -----------------------------------------------------------------------
// NTLM fingerprinting (CredSSP / NLA)
// -----------------------------------------------------------------------

// ntlmFingerprint sends an NTLM Negotiate message over an already-
// established TLS connection and parses the Challenge to populate OS
// version, domain, and host fields on result.
func ntlmFingerprint(conn net.Conn, result *RDPResult) (zgrab2.ScanStatus, error) {
	_, err := conn.Write(NTLM_NEGOTIATE_BLOB)
	responseBytes, readErr := zgrab2.ReadAvailable(conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), err
	}
	if readErr != nil {
		return zgrab2.TryGetScanStatus(readErr), readErr
	}

	prefixOffset := bytes.Index(responseBytes, NTLM_PREFIX)
	if prefixOffset == -1 {
		return zgrab2.SCAN_PROTOCOL_ERROR, errors.New("not a valid NTLMSSP response")
	}

	if len(responseBytes) < prefixOffset+NTLM_RESPONSE_LENGTH {
		return zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("invalid response length %d", len(responseBytes))
	}

	var responseData NTLMSecurityBlob
	responseBytes = responseBytes[prefixOffset:]
	responseBuf := bytes.NewBuffer(responseBytes)

	err = binary.Read(responseBuf, binary.LittleEndian, &responseData)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), err
	}

	if responseData.MessageType != 0x2 {
		return zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("unexpected message type %d", responseData.MessageType)
	}

	if responseData.Reserved != 0 {
		return zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("reserved value is not zero %d", responseData.Reserved)
	}

	if !reflect.DeepEqual(responseData.Version[4:], []byte{0, 0, 0, 0xF}) {
		return zgrab2.SCAN_PROTOCOL_ERROR, errors.New("unknown OS info structure in NTLM handshake")
	}

	ntlmInfo := new(ntlm.Info)
	result.NTLM = ntlmInfo

	ntlmInfo.OSVersion = ntlm.VersionFromBytes(responseData.Version[:])

	// Parse: TargetName (DomainName field in the challenge)
	targetNameLen := int(responseData.DomainNameLen)
	if targetNameLen > 0 {
		startIndex := int(responseData.DomainNameBufferOffset)
		endIndex := startIndex + targetNameLen
		if endIndex > len(responseBytes) {
			return zgrab2.SCAN_PROTOCOL_ERROR, errors.New("invalid DomainNameLen value")
		}
		ntlmInfo.TargetName = strings.ReplaceAll(string(responseBytes[startIndex:endIndex]), "\x00", "")
	}

	// Parse: TargetInfo AV_PAIRs
	targetInfoLen := int(responseData.TargetInfoLen)
	if targetInfoLen > 0 {
		startIndex := int(responseData.TargetInfoBufferOffset)
		if startIndex+targetInfoLen > len(responseBytes) {
			return zgrab2.SCAN_PROTOCOL_ERROR, errors.New("invalid TargetInfoLen value")
		}

		var avItem *AVItem
		currentIndex := startIndex

		avItem, err = readAvItem(responseBytes, startIndex, currentIndex, targetInfoLen)
		if err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, err
		}

		var pairs []ntlm.AvPairEntry
		for avItem.Id != AV_EOL {
			avLength := AV_ITEM_LENGTH + int(avItem.Length)
			pairs = append(pairs, &rdpAvPair{
				id:    avItem.Id,
				value: responseBytes[currentIndex+AV_ITEM_LENGTH : currentIndex+avLength],
			})
			currentIndex += avLength
			avItem, err = readAvItem(responseBytes, startIndex, currentIndex, targetInfoLen)
			if err != nil {
				return zgrab2.SCAN_PROTOCOL_ERROR, err
			}
		}
		ntlm.InfoFromAvPairs(ntlmInfo, pairs)
	}
	return zgrab2.SCAN_SUCCESS, nil
}

// rdpAvPair adapts the RDP AV_PAIR parsing to the shared ntlm.AvPairEntry interface.
type rdpAvPair struct {
	id    uint16
	value []byte
}

func (p *rdpAvPair) GetAvID() uint16  { return p.id }
func (p *rdpAvPair) GetValue() []byte { return p.value }

func readAvItem(responseBytes []byte, startIndex int, currentIndex int, targetInfoLen int) (*AVItem, error) {
	var avItem AVItem
	nextIndex := currentIndex + AV_ITEM_LENGTH
	if nextIndex > startIndex+targetInfoLen {
		return nil, errors.New("invalid AV Item list")
	}
	if nextIndex > len(responseBytes) {
		return nil, errors.New("invalid AV Item list")
	}
	avItemBuf := bytes.NewBuffer(responseBytes[currentIndex:nextIndex])
	err := binary.Read(avItemBuf, binary.LittleEndian, &avItem)
	if err != nil {
		return nil, err
	}
	return &avItem, nil
}
