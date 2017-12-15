package zgrab2

// Scanner is an interface that represents all functions necessary to run a scan
type Scanner interface {
	// Init runs once for this module at library init time
	Init(flags ScanFlags) error

	// InitPerSender runs once per Goroutine. A single Goroutine will scan some non-deterministic
	// subset of the input scan targets
	InitPerSender(senderID int) error

	// Returns the name passed at init
	GetName() string

	// Scan connects to a host. The result should be JSON-serializable
	Scan(t ScanTarget) (ScanStatus, interface{}, error)
}

type ScanStatus string

// TODO: Confirm to standard string const format (names, capitalization, hyphens/underscores, etc)
// TODO: Enumerate further status types
const (
	SCAN_SUCCESS            = "success"
	SCAN_CONNECTION_REFUSED = "connection-refused" // TCP connection was actively rejected
	SCAN_CONNECTION_TIMEOUT = "connection-timeout" // No response to TCP connection request
	SCAN_CONNECTION_CLOSED  = "connection-closed"  // The TCP connection was unexpectedly closed
	SCAN_IO_TIMEOUT         = "io-timeout"         // Timed out waiting on data
	SCAN_PROTOCOL_ERROR     = "protocol-error"     // Received data incompatible with the target protocol
	SCAN_APPLICATION_ERROR  = "application-error"  // The application reported an error
	SCAN_UNKNOWN_ERROR      = "unknown-error"      // Catch-all for unrecognized errors
)

// ScanResponse is the result of a scan on a single host
type ScanResponse struct {
	// Status is required for all responses. Other fields are optional.
	Status    ScanStatus  `json:"status"`
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
	Port    uint   `short:"p" long:"port" description:"Specify port to grab on"`
	Name    string `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple modules"`
	Timeout uint   `short:"t" long:"timeout" description:"Set connection timeout in seconds"`
}

// GetName returns the name of the respective scanner
func (b *BaseFlags) GetName() string {
	return b.Name
}

// GetModule returns the registered module that corresponds to the given name
// or nil otherwise
func GetModule(name string) *ScanModule {
	return modules[name]
}

var modules map[string]*ScanModule

func init() {
	modules = make(map[string]*ScanModule)
}
