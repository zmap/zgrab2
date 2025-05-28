package zgrab2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/censys/cidranger"
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

	// Scan connects to a host. The result should be JSON-serializable. If a scan requires a dialer that isn't set in
	// the dialer group, an error will return.
	Scan(ctx context.Context, dialerGroup *DialerGroup, t *ScanTarget) (ScanStatus, any, error)

	// GetDialerGroupConfig returns a DialerGroupConfig that the framework will use to set up the dialer group using the module's
	// desired dialer configuration.
	GetDialerGroupConfig() *DialerGroupConfig
}

// TransportProtocol is an enum for the transport layer protocol of a module
type TransportProtocol uint

const (
	reservedTransportProtocol TransportProtocol = iota // 0 is reserved so we can ensure the caller set this explicitly
	TransportTCP
	TransportUDP
)

// DialerGroupConfig lets modules communicate what they'd need in a dialer group. The framework uses this to configure
// a default dialer group for the module.
type DialerGroupConfig struct {
	// TransportAgnosticDialerProtocol is the L4 transport the module uses by convention (ex: SSH over TCP).
	// This is only used to configure the DialerGroup.TransportAgnosticDialer. The L4Dialer can handle both UDP and TCP.
	TransportAgnosticDialerProtocol TransportProtocol
	// NeedSeparateL4Dialer indicates whether the module needs a dedicated L4 dialer in its DialerGroup.
	// Some modules' protocols need to send some command (STARTTLS) after L4 connection and before TLS handshake.
	// Others like http need to follow redirects to https:// and http:// servers, which requires both a TLS and L4 (TCP) conn.
	// Still others may require a dialer that can handle both TCP and UDP.
	// If this is true, the framework will ensure dialerGroup.L4Dialer is set.
	// If false, the framework will set the TransportAgnosticDialer
	NeedSeparateL4Dialer bool
	BaseFlags            *BaseFlags
	// TLSEnabled indicates whether the module needs a TLS connection. The behavior depends on if NeedsL4Dialer is true.
	// If NeedsL4Dialer is true, the framework will set up a TLSWrapper in the DialerGroup so a module can access both.
	// If NeedsL4Dialer is false, the framework will set up a TLS dialer as the TransportAgnosticDialer since the module
	// has indicated it only needs a TLS connection.
	TLSEnabled bool
	TLSFlags   *TLSFlags // must be non-nil if TLSEnabled is true
}

// Validate checks for various incompatibilities in the DialerGroupConfig
func (config *DialerGroupConfig) Validate() error {
	if config.BaseFlags == nil {
		return errors.New("BaseFlags must be set")
	}
	switch config.TransportAgnosticDialerProtocol {
	case TransportUDP:
		if config.TLSEnabled {
			// blocking this for now since it's untested. When a module is added that needs this we can unblock it and test.
			return errors.New("TLS-over-UDP (DTLS) is not currently supported")
		}
	case TransportTCP, reservedTransportProtocol:
		// nothing to validate here
	default:
		return fmt.Errorf("invalid TransportAgnosticDialerProtocol: %d", config.TransportAgnosticDialerProtocol)
	}
	if config.TLSEnabled && config.TLSFlags == nil {
		return errors.New("TLS flags must be set if TLSEnabled is true")
	}
	return nil
}

func (config *DialerGroupConfig) GetDefaultDialerGroupFromConfig() (*DialerGroup, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config did not pass validation: %w", err)
	}
	dialerGroup := new(DialerGroup)
	// DialerGroup has two types of dialers, the L4Dialer and the TransportAgnosticDialer.
	// A module will use one or the other based on NeedSeparateL4Dialer
	if config.NeedSeparateL4Dialer {
		dialerGroup.L4Dialer = func(scanTarget *ScanTarget) func(ctx context.Context, network, addr string) (net.Conn, error) {
			return func(ctx context.Context, network, addr string) (net.Conn, error) {
				switch network {
				case "udp", "udp4", "udp6":
					return GetDefaultUDPDialer(config.BaseFlags)(ctx, scanTarget, addr)
				case "tcp", "tcp4", "tcp6":
					return GetDefaultTCPDialer(config.BaseFlags)(ctx, scanTarget, addr)
				default:
					return nil, fmt.Errorf("unsupported network type: %s", network)
				}
			}
		}
		if config.TLSEnabled {
			// module needs both L4 dialer and TLS wrapper
			dialerGroup.TLSWrapper = GetDefaultTLSWrapper(config.TLSFlags)
		}
	} else {
		// module only needs a TransportAgnosticDialer
		if config.TLSEnabled {
			dialerGroup.TransportAgnosticDialer = func(ctx context.Context, target *ScanTarget) (net.Conn, error) {
				// TransportAgnosticDialer only connects to a single target
				address := net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port)))
				return GetDefaultTLSDialer(config.BaseFlags, config.TLSFlags)(ctx, target, address)
			}
		} else {
			// module only needs a TransportAgnosticDialer, so we set it based on the protocol
			switch config.TransportAgnosticDialerProtocol {
			case TransportUDP:
				dialerGroup.TransportAgnosticDialer = func(ctx context.Context, target *ScanTarget) (net.Conn, error) {
					// TransportAgnosticDialer only connects to a single target
					address := net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port)))
					return GetDefaultUDPDialer(config.BaseFlags)(ctx, target, address)
				}
			case TransportTCP:
				dialerGroup.TransportAgnosticDialer = func(ctx context.Context, target *ScanTarget) (net.Conn, error) {
					// TransportAgnosticDialer only connects to a single target
					address := net.JoinHostPort(target.Host(), strconv.Itoa(int(target.Port)))
					return GetDefaultTCPDialer(config.BaseFlags)(ctx, target, address)
				}
			default:
				return nil, fmt.Errorf("unsupported TransportAgnosticDialerProtocol: %d", config.TransportAgnosticDialerProtocol)
			}
		}
	}
	return dialerGroup, nil
}

// DialerGroup wraps various dialer functions for a module to use. A module will usually only use a subset of these,
// and will indicate which ones it needs in the DialerGroupConfig.
type DialerGroup struct {
	// TransportAgnosticDialer should be used by most modules that do not need control over the transport layer.
	// It abstracts the underlying transport protocol so a module can  deal with just the L7 logic. Any protocol that
	// doesn't need to know about the underlying transport should use this.
	// If the transport is a TLS connection, the dialer should return a zgrab2.TLSConnection so the underlying log can be
	// accessed.
	TransportAgnosticDialer func(ctx context.Context, target *ScanTarget) (net.Conn, error)
	// L4Dialer will be used by any module that needs to have a TCP/UDP connection. Think of following a redirect to an
	// http:// server, or a module that needs to start with a TCP connection and then upgrade to TLS as part of the protocol.
	// The layered function is needed since we set DialerGroups at Scanner.Init, but modules like HTTP will modify the
	// Dialer based on the target, for example to use a fake DNS resolver based on the domain name.
	L4Dialer func(target *ScanTarget) func(ctx context.Context, network, addr string) (net.Conn, error)
	// TLSWrapper is a function that takes an existing net.Conn and upgrades it to a TLS connection. This is useful for
	// modules that need to start with a TCP connection and then upgrade to TLS later as part of the protocol.
	// Cannot be used for QUIC connections, as QUIC connections are not "upgraded" from a L4 connection
	TLSWrapper func(ctx context.Context, target *ScanTarget, l4Conn net.Conn) (*TLSConnection, error)
	Blocklist  *cidranger.Ranger // Blocklist is a list of CIDR ranges that should be blocked
}

// Dial is used to access the transport agnostic dialer
func (d *DialerGroup) Dial(ctx context.Context, target *ScanTarget) (net.Conn, error) {
	if d.TransportAgnosticDialer == nil {
		return nil, errors.New("no transport agnostic dialer set")
	}
	return d.TransportAgnosticDialer(ctx, target)
}

// GetTLSDialer returns a function that can be used as a standalone TLS dialer. This is useful for modules like HTTP that
// require this for handling redirects to https://
func (d *DialerGroup) GetTLSDialer(ctx context.Context, t *ScanTarget) func(network, addr string) (*TLSConnection, error) {
	return func(network, addr string) (*TLSConnection, error) {
		if d.TLSWrapper == nil {
			return nil, errors.New("no TLS wrapper set")
		}
		if d.L4Dialer == nil {
			return nil, errors.New("no L4 dialer set")
		}
		conn, err := d.L4Dialer(t)(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("could not initiate a L4 connection with L4 dialer: %w", err)
		}
		return d.TLSWrapper(ctx, t, conn)
	}
}

// ScanResponse is the result of a scan on a single host
type ScanResponse struct {
	// Status is required for all responses.
	Status ScanStatus `json:"status"`

	// Protocol is the identifier if the protocol that did the scan. In the case of a complex scan, this may differ from
	// the scan name.
	Protocol string `json:"protocol"`

	Result    any     `json:"result,omitempty"`
	Timestamp string  `json:"timestamp,omitempty"`
	Error     *string `json:"error,omitempty"`
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

	// Validate enforces all command-line flags and positional arguments have valid values.
	Validate([]string) error
}

// BaseFlags contains the options that every flags type must embed
type BaseFlags struct {
	Port           uint          `short:"p" long:"port" description:"Specify port to grab on"`
	Name           string        `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple modules"`
	ConnectTimeout time.Duration `long:"connect-timeout" description:"Set max for how long to wait for initial connection establishment (0 = no timeout)" default:"10s"`
	TargetTimeout  time.Duration `short:"t" long:"target-timeout" description:"Set max for how long a scan of a single target (IP, Domain, etc) can take (0 = no timeout)" default:"60s"`
	Trigger        string        `short:"g" long:"trigger" description:"Invoke only on targets with specified tag"`
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
