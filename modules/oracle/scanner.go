// Package oracle provides a zgrab2 module that proves for oracle.
// TODO: Describe module, the flags, the probe, the output, etc.
package oracle

import (
	"github.com/jb/tcpwrap"
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

	// TODO: Find version number mappings and take a string here instead
	Version                uint16 `long:"version" description:"The client version number to send." default:"312"`
	MinVersion             uint16 `long:"min-version" description:"The minimum supported client version to send in the connect packet." default:"300"`
	ReleaseVersion         string `long:"release-version" description:"The dotted-decimal release version used during the SNS negoatiation. Must contain five components (e.g. 1.2.3.4.5)." default:"11.2.0.4.0"`
	GlobalServiceOptions   string `long:"global-service-options" description:"The Global Service Options flags to send in the connect packet." default:"0x0C41"`
	SDU                    string `long:"sdu" description:"The SDU value to send in the connect packet." default:"0x2000"`
	TDU                    string `long:"tdu" description:"The TDU value to send in the connect packet." default:"0xFFFF"`
	ProtocolCharacterisics string `long:"protocol-characteristics" description:"The Protocol Characteristics flags to send in the connect packet." default:"0x7F08"`
	ConnectFlags           string `long:"connect-flags" description:"The connect flags for the connect packet." default:"0x4141"`
	ConnectDescriptor      string `long:"connect-descriptor" description:"The connect descriptor to use in the connect packet. TODO: find a good default"`
	TCPS                   bool   `long:"tcps" description:"Wrap the connection with a TLS handshake."`
	Verbose                bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
	// TODO: Add any module-global state
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	// TODO: Add scan state
}

// RegisterModule() registers the zgrab2 module.
func RegisterModule() {
	var module Module
	// FIXME: Set default port
	_, err := zgrab2.AddCommand("oracle", "oracle", "Probe for oracle", 1521, &module)
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

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
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

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

// Scan() TODO: describe what is scanned
func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var results *ScanResults = nil

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
		conn:    tcpwrap.Wrap(sock),
		scanner: scanner,
		target:  &t,
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
		return zgrab2.TryGetScanStatus(err), results, err
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}
