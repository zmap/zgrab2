package zgrab2

import (
	"math/rand"
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

	// Scan connects to a host. The result should be JSON-serializable
	Scan(t ScanTarget) (ScanStatus, interface{}, error)
}

// ScanResponse is the result of a scan on a single host
type ScanResponse struct {
	// Status is required for all responses.
	Status ScanStatus `json:"status"`

	// Protocol is the identifier if the protocol that did the scan. In the case of a complex scan, this may differ from
	// the scan name.
	Protocol string `json:"protocol"`

	Result    interface{} `json:"result,omitempty"`
	Timestamp string      `json:"timestamp,omitempty"`
	Error     *string     `json:"error,omitempty"`
}

// ScanModule is an interface which represents a module that the framework can
// manipulate
type ScanModule interface {
	// NewFlags is called by the framework to pass to the argument parser. The parsed flags will be passed
	// to the scanner created by NewScanner().
	NewFlags() interface{}

	// NewScanner is called by the framework for each time an individual scan is specified in the config or on
	// the command-line. The framework will then call scanner.Init(name, flags).
	NewScanner() Scanner
}

// ScanFlags is an interface which must be implemented by all types sent to
// the flag parser
type ScanFlags interface {
	// Help optionally returns any additional help text, e.g. specifying what empty defaults
	// are interpreted as.
	Help() string

	// Validate enforces all command-line flags and positional arguments have valid values.
	Validate(args []string) error
}

// BaseFlags contains the options that every flags type must embed
type BaseFlags struct {
	Port            uint          `short:"p" long:"port" description:"Specify port to grab on"`
	Name            string        `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple modules"`
	Timeout         time.Duration `short:"t" long:"timeout" description:"Set connection timeout (0 = no timeout)" default:"10s"`
	Trigger         string        `short:"g" long:"trigger" description:"Invoke only on targets with specified tag"`
	BytesReadLimit  int           `short:"m" long:"maxbytes" description:"Maximum byte read limit per scan (0 = defaults)"`
	SourceIPv4Range string        `long:"source-ip" description:"Local source IP address to use for making connections (IPv4 only)"`
	sourceIPs       []net.IP
}

// UDPFlags contains the common options used for all UDP scans
type UDPFlags struct {
	LocalPort    uint   `long:"local-port" description:"Set an explicit local port for UDP traffic"`
	LocalAddress string `long:"local-addr" description:"Set an explicit local address for UDP traffic"`
}

// AfterParse is called after the flags are parsed by the module, to perform
// additional verification or initialization.
func (b *BaseFlags) AfterParse() error {
	if b.SourceIPv4Range != "" {
		ips, err := ParseIPv4RangeString(b.SourceIPv4Range)
		if err != nil {
			return err
		}
		b.sourceIPs = ips
	}
	return nil
}

// GetRandomSourceIP (non-cryptographically) randomly selects an IP from its set
// of source IPs. If no source IPs were specified, this function returns nil.
func (b *BaseFlags) GetRandomSourceIP() net.IP {
	sourceIPCount := len(b.sourceIPs)
	if sourceIPCount == 0 {
		return nil
	}
	if sourceIPCount == 1 {
		return b.sourceIPs[0]
	}
	idx := rand.Intn(sourceIPCount)
	return b.sourceIPs[idx]
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
