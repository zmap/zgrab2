// Package oracle provides the zgrab2 scanner module for Oracle's TNS protocol.
// Default Port: 1521 (TCP)
//
// The scan does the first part of a TNS handshake, prior to the point where
// any actual authentication is required; the happy case goes
// 1. client-to-server: Connect(--client-version, --min-server-version, --connect-descriptor)
// 2. server-to-client: Resend
// 3. client-to-server: Connect(exact same data)
// 4. server-to-client: Accept(server_version)
// 5. client-to-server: Data: Native Service Negotiation
// 6. server-to-client: Data: Native Service Negotiation(component release versions)
//
// The default scan uses a generic connect descriptor with no explicit connect
// data / service name, so it relies on the server to choose the destination.
//
// Sending an intentionally invalid --connect-descriptor can force a Refuse
// response, which should include a version number.
//
// The output includes the server's protocol version and any component release
// versions that are returned.
package oracle

import (
	"fmt"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// Handshake is the log of the TNS handshake between client and server.
	Handshake *HandshakeLog `json:"handshake,omitempty"`

	// TLSLog contains the log of the TLS handshake (and any additional
	// configured TLS scan operations).
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the HTTP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags

	// Version is the client version number sent to the server in the Connect
	// packet. TODO: Find version number mappings.
	Version uint16 `long:"client-version" description:"The client version number to send." default:"312"`

	// MinVersion is the minimum protocol version that the client claims support
	// for in the Connect packet. Same format as Version above.
	MinVersion uint16 `long:"min-server-version" description:"The minimum supported client version to send in the connect packet." default:"300"`

	// ReleaseVersion is the five-component dotted-decimal release version
	// string the client should send during native Native Security Negotiation.
	ReleaseVersion string `long:"release-version" description:"The dotted-decimal release version used during the NSN negoatiation. Must contain five components (e.g. 1.2.3.4.5)." default:"11.2.0.4.0"`

	// GlobalServiceOptions sets the ServiceOptions flags the client will send
	// to the server in the Connect packet. 16 bits.
	GlobalServiceOptions string `long:"global-service-options" description:"The Global Service Options flags to send in the connect packet." default:"0x0C41"`

	// SDU sets the requested Session Data Unit size value the client sends in
	// the Connect packet. 16 bits.
	SDU string `long:"sdu" description:"The SDU value to send in the connect packet." default:"0x2000"`

	// TDU sets the request Transport Data Unit size value the client sends in
	// the Connect packet. 16 bits.
	TDU string `long:"tdu" description:"The TDU value to send in the connect packet." default:"0xFFFF"`

	// ProtocolCharacteristics sets the protocol characteristics flags the
	// client sends to the server in the Connect packet. 16 bits.
	ProtocolCharacterisics string `long:"protocol-characteristics" description:"The Protocol Characteristics flags to send in the connect packet." default:"0x7F08"`

	// ConnectFlags sets the connect flags the client sends to the server in the
	// Connect packet. The upper 16 bits give the first byte, the lower 16 bits
	// the second byte.
	ConnectFlags string `long:"connect-flags" description:"The connect flags for the connect packet." default:"0x4141"`

	// ConnectDescriptor sets the connect descriptor the client sends in the
	// data payload of the Connect packet.
	// See https://docs.oracle.com/cd/E11882_01/network.112/e41945/glossary.htm#BGBEAGEA
	ConnectDescriptor string `long:"connect-descriptor" description:"The connect descriptor to use in the connect packet."`

	// TCPS determines whether the connection starts with a TLS handshake.
	TCPS bool `long:"tcps" description:"Wrap the connection with a TLS handshake."`

	// NewTNS causes the client to use the newer TNS header format with 32-bit
	// lengths.
	NewTNS bool `long:"new-tns" description:"If set, use new-style TNS headers"`

	// Verbose causes more verbose logging, and includes debug fields inthe scan
	// results.
	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("oracle", "oracle", module.Description(), 1521, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Perform a handshake with Oracle database servers"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
	u16Strings := map[string]string{
		"global-service-options":   flags.GlobalServiceOptions,
		"protocol-characteristics": flags.ProtocolCharacterisics,
		"connect-flags":            flags.ConnectFlags,
		"sdu":                      flags.SDU,
		"tdu":                      flags.TDU,
	}
	for name, value := range u16Strings {
		v, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return fmt.Errorf("%s: %s is not a valid 16-bit integer: %v", name, value, err)
		}
		if v > 0xffff {
			return fmt.Errorf("%s: %s is larger than 16 bits", name, value)
		}
	}
	if _, err := EncodeReleaseVersion(flags.ReleaseVersion); err != nil {
		return fmt.Errorf("release-version: %s is not a valid five-component dotted-decimal number", flags.ReleaseVersion)
	}
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
	if f.Verbose {
		log.SetLevel(log.DebugLevel)
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
	return "oracle"
}

func (scanner *Scanner) getTNSDriver() *TNSDriver {
	mode := TNSModeOld
	if scanner.config.NewTNS {
		mode = TNSMode12c
	}
	return &TNSDriver{Mode: mode}
}

// Scan does the following:
//  1. Make a TCP connection to the target
//  2. If --tcps is set, do a TLS handshake and use the wrapped socket in future
//     calls.
//  3. Instantiate the TNS driver (TNSMode12c if --new-tns is set, otherwise
//     TNSModeOld)
//  4. Send the Connect packet to the server with the provided options and
//     connect descriptor
//  5. If the server responds with a valid TNS packet, an Oracle server has been
//     detected. If not, fail.
//  6. If the response is...
//     a. ...a Resend packet, then set result.DidResend and re-send the packet.
//     b. ...a Refused packet, then set the result.RefuseReason and RefuseError,
//        then exit.
//     c. ...a Redirect packet, then set result.RedirectTarget and exit.
//     d. ...an Accept packet, go to 7
//     e. ...anything else: exit with SCAN_APPLICATION_ERROR
//  7. Pull the server protocol version and other flags from the Accept packet
//     into the results, then send a Native Security Negotiation Data packet.
//  8. If the response is not a Data packet, exit with SCAN_APPLICATION_ERROR.
//  9. Pull the versions out of the response and exit with SCAN_SUCCESS.
func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var results *ScanResults

	sock, err := t.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if scanner.config.TCPS {
		tlsConn, err := scanner.config.TLSFlags.GetTLSConnection(sock)
		if err != nil {
			// GetTLSConnection can only fail if the input flags are bad
			panic(err)
		}
		results = new(ScanResults)
		results.TLSLog = tlsConn.GetLog()
		err = tlsConn.Handshake()
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}
		sock = tlsConn
	}

	conn := Connection{
		conn:      sock,
		scanner:   scanner,
		target:    &t,
		tnsDriver: scanner.getTNSDriver(),
	}
	connectDescriptor := scanner.config.ConnectDescriptor
	if connectDescriptor == "" {
		// In local testing, omitting the SERVICE_NAME allowed the server to
		// choose an appropriate default. CID.PROGRAM added strictly for logging
		// purposes.
		connectDescriptor = "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=zgrab2))))"
	}
	handshakeLog, err := conn.Connect(connectDescriptor)
	if handshakeLog != nil {
		// Ensure that any handshake logs, even if incomplete, get returned.
		if results == nil {
			// If the results were not created previously to store the TLS log,
			// create it now
			results = new(ScanResults)
		}
		results.Handshake = handshakeLog
	}

	if err != nil {
		switch err {
		case ErrUnexpectedResponse:
			return zgrab2.SCAN_APPLICATION_ERROR, results, err
		default:
			return zgrab2.TryGetScanStatus(err), results, err
		}
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}
