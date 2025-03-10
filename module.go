package zgrab2

import (
	"context"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/zmap/zcrypto/tls"
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
	Scan(ctx context.Context, t *ScanTarget, dialer *DialerGroup) (ScanStatus, any, error)

	// GetDefaultDialerGroup returns the default dialer group for this scanner. A module should set the dialers it needs
	// in init for the framework to use.
	GetDefaultDialerGroup() *DialerGroup

	// SupportsTLS whether a module supports TLS by default
	SupportsTLS() bool

	// GetDefaultTransportProtocol returns the default l4 transport protocol for this scanner
	GetDefaultTransportProtocol() TransportProtocol
}

type TransportProtocol uint

const (
	TransportTCP TransportProtocol = iota
	TransportUDP
)

type TLSWrapper func(ctx context.Context, target *ScanTarget, l4Conn net.Conn) (*TLSConnection, error)

type DialerGroup struct {
	// DefaultDialer should be used by most modules that do not need control over the transport layer.
	// It abstracts the underlying transport protocol so a module can  deal with just the L7 logic. Any protocol that
	// doesn't need to know about the underlying transport should use this.
	// If the transport is a TLS connection, the dialer should provide a zgrab2.TLSConnection so the underlying log can be
	// accessed.
	DefaultDialer func(ctx context.Context, target *ScanTarget) (net.Conn, error)
	// L4Dialer will be used by any module that needs to have a TCP/UDP connection. Think of following a redirect to an
	// http:// server, or a module that needs to start with a TCP connection and then upgrade to TLS as part of the protocol.
	L4Dialer func(ctx context.Context, network, address string) (net.Conn, error)
	// TLSWrapper is a function that takes an existing net.Conn and upgrades it to a TLS connection. This is useful for
	// modules that need to start with a TCP connection and then upgrade to TLS later as part of the protocol.
	// Cannot be used for QUIC connections, as QUIC connections are not "upgraded" from a L4 connection
	TLSWrapper func(ctx context.Context, target *ScanTarget, l4Conn net.Conn) (*TLSConnection, error)

	// Below are to support QUIC, we need the following: https://quic-go.net/docs/http3/client/
	// https://pkg.go.dev/github.com/quic-go/quic-go/http3#Transport Needed for full control over this
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
	// We'll likely need to impose our own type on quic.EarlyConnection to get the same log info we have in TLS logs
	// TODO Phillip update below when we have QUIC support
	QUICDialer func(ctx context.Context, target *ScanTarget, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error)
}

// Dial is used to access the default dialer
func (d *DialerGroup) Dial(ctx context.Context, target *ScanTarget) (net.Conn, error) {
	return d.DefaultDialer(ctx, target)
}

func (d *DialerGroup) SetDefaultDialer(dialer func(ctx context.Context, target *ScanTarget) (net.Conn, error)) {
	d.DefaultDialer = dialer
}

func (d *DialerGroup) GetL4Dialer() func(ctx context.Context, network, address string) (net.Conn, error) {
	return d.L4Dialer
}

func (d *DialerGroup) GetTLSWrapper() func(ctx context.Context, target *ScanTarget, l4Conn net.Conn) (*TLSConnection, error) {
	return d.TLSWrapper
}

// GetTLSDialer returns a function that can be used as a standalone TLS dialer. This is useful for modules like HTTP that
// require this for handling redirects to https://
func (d *DialerGroup) GetTLSDialer(ctx context.Context, t *ScanTarget) func(network, addr string) (*TLSConnection, error) {
	return func(network, addr string) (*TLSConnection, error) {
		conn, err := d.L4Dialer(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("could not initiate a L4 connection with L4 dialer: %v", err)
		}
		return d.TLSWrapper(ctx, t, conn)
	}
}

// TODO some handling of the TLS/QUIC Dialer for http module
//func (d *DialerGroup) GetEncryptedDialer

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
