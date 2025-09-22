package modules

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

type TLSFlags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`
}

type TLSModule struct {
}

type TLSScanner struct {
	config            *TLSFlags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

func init() {
	var tlsModule TLSModule
	_, err := zgrab2.AddCommand("tls", "Transport Layer Security (TLS)", tlsModule.Description(), 443, &tlsModule)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *TLSModule) NewFlags() any {
	return new(TLSFlags)
}

func (m *TLSModule) NewScanner() zgrab2.Scanner {
	return new(TLSScanner)
}

// Description returns an overview of this module.
func (m *TLSModule) Description() string {
	return "Perform a TLS handshake"
}

func (f *TLSFlags) Validate(_ []string) error {
	return nil
}

func (f *TLSFlags) Help() string {
	return ""
}

func (s *TLSScanner) Init(flags zgrab2.ScanFlags) error {
	f, ok := flags.(*TLSFlags)
	if !ok {
		return zgrab2.ErrMismatchedFlags
	}
	s.config = f
	s.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      true,
		TLSFlags:                        &f.TLSFlags,
	}
	return nil
}

func (s *TLSScanner) GetName() string {
	return s.config.Name
}

func (s *TLSScanner) GetTrigger() string {
	return s.config.Trigger
}

func (s *TLSScanner) InitPerSender(senderID int) error {
	return nil
}

// Scan opens a TCP connection to the target (default port 443), then performs
// a TLS handshake. If the handshake gets past the ServerHello stage, the
// handshake log is returned (along with any other TLS-related logs, such as
// heartbleed, if enabled).
func (s *TLSScanner) Scan(ctx context.Context, dialerGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialerGroup.Dial(ctx, target)
	if conn != nil {
		defer zgrab2.CloseConnAndHandleError(conn)
	}
	if err != nil {
		// Even on an error, we want to give the TLS Log if we have it.
		if conn != nil {
			if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok {
				if tlsLog := tlsConn.GetLog(); tlsLog != nil {
					if tlsLog.HandshakeLog.ServerHello != nil {
						// If we got far enough to get a valid ServerHello, then
						// consider it to be a positive TLS detection.
						return zgrab2.TryGetScanStatus(err), tlsLog, err
					}
					// Otherwise, detection failed.
				}
			}
		}
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	tlsConn, ok := conn.(*zgrab2.TLSConnection)
	if !ok {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, errors.New("scan returned non-TLS connection")
	}
	return zgrab2.SCAN_SUCCESS, tlsConn.GetLog(), nil
}

// Protocol returns the protocol identifer for the scanner.
func (s *TLSScanner) Protocol() string {
	return "tls"
}

func (s *TLSScanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return s.dialerGroupConfig
}

// GetScanMetadata returns any metadata on the scan itself from this module.
func (s *TLSScanner) GetScanMetadata() any {
	return nil
}
