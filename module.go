package zgrab2

import (
	"context"
	"net"
	"time"
)

// Scanner is an interface that represents all functions necessary to run a scan
type Scanner interface {
	// Init runs once for this module at library init time
	Init(flags ScanFlags) error

	// InitPerSender runs once per Goroutine. A single Goroutine will scan some non-deterministic
	// subset of the input scan targets
	InitPerSender(senderID int) error

	// Returns the name passed at init
	GetName() string

	// Returns the trigger passed at init
	GetTrigger() string

	// Protocol returns the protocol identifier for the scan.
	Protocol() string

	// Scan connects to a scan target
	// If existingConn is non-nil, the scanner should use this connection. The connection will *not* be closed by the scanner.
	// If existingConn is nil, the scanner should open a new connection to the target. The scanner is responsible for closing the connection.
	// The result should be JSON-serializable
	Scan(target ScanTarget, existingConn net.Conn) (result any, status ScanStatus, err error)

	// WithDialContext allows a module user to specify a custom dialer to be used for the scan.
	// This custom dialer should be used by the scanner whenever an existingConn is *nil*.
	// The scanner should ignore any SourceIP or SourcePort when using the custom dialer, setting SourceIP/Port becomes the responsibility of the custom dialer.
	WithDialContext(dialer ContextDialer)
}

type ContextDialer func(ctx context.Context, network string, addr string) (net.Conn, error)

// ScanResponse is the result of a scan on a single host
type ScanResponse struct {
	IsSuccess bool    `json:"success"`
	Error     *string `json:"error,omitempty"`
	// Status is required for all responses.
	Status ScanStatus `json:"status"`

	ScannerName string `json:"module_name,omitempty"`
	// Protocol is the identifier if the protocol that did the scan. In the case of a complex scan, this may differ from
	// the scan name.
	Protocol string `json:"protocol,omitempty"`

	Result    any    `json:"result,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// ScanModule is an interface which represents a module that the framework can manipulate
type ScanModule interface {
	// NewFlags is called by the framework to pass to the argument parser. The parsed flags will be passed
	// to the scanner created by NewScanner().
	NewFlags() any

	// NewScanner is called by the framework for each time an individual scan is specified in the config or on
	// the command-line. The framework will then call scanner.Init(name, flags).
	NewScanner() Scanner

	// Description returns a string suitable for use as an overview of this module within usage text.
	Description() string
}

// ScanFlags is an interface which must be implemented by all types sent to
// the flag parser
type ScanFlags interface {
	// Help optionally returns any additional help text, e.g. specifying what empty defaults are interpreted as.
	Help() string

	// Validate enforces all flags have valid values.
	Validate() error
}

// BaseFlags contains the options that every flags type must embed
type BaseFlags struct {
	Port           uint          `short:"p" long:"port" description:"Specify port to grab on"`
	BytesReadLimit int           `short:"m" long:"maxbytes" description:"Maximum byte read limit per scan (0 = defaults)"`
	Name           string        `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple modules"`
	Timeout        time.Duration `short:"t" long:"timeout" description:"Set connection timeout (0 = no timeout)" default:"10s"`
	Trigger        string        `short:"g" long:"trigger" description:"Invoke only on targets with specified tag"`
}

// UDPFlags contains the common options used for all UDP scans
type UDPFlags struct {
	LocalPort    uint   `long:"local-port" description:"Set an explicit local port for UDP traffic"`
	LocalAddress string `long:"local-addr" description:"Set an explicit local address for UDP traffic"`
}

// GetName returns the name of the respective scanner
func (b *BaseFlags) GetName() string {
	return b.Name
}

// GetModule returns the registered module that corresponds to the given name
// or nil otherwise
func GetModule(name string) ScanModule {
	return modules[name]
}

var modules map[string]ScanModule

func init() {
	modules = make(map[string]ScanModule)
}
