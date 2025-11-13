// Package main provides a zgrab2 module that scans for ManageSieve servers.
// ManageSieve is a protocol for remotely managing Sieve scripts used for email filtering.
// Default port: 4190 (TCP)
//
// RFC 5804: https://tools.ietf.org/html/rfc5804
package managesieve

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the ManageSieve scan module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`
	BannerTimeout    time.Duration `long:"banner-timeout" description:"Set max for how long to wait for server to send capabilities after connection establishment (0 = no timeout)" default:"10s"`
}

// Module implements the zgrab2.Module interface.
type Module struct{}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config            *Flags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// ScanResults holds the results of a ManageSieve scan.
type ScanResults struct {
	// Banner is the initial server greeting
	Banner string `json:"banner,omitempty"`

	// Capabilities contains the server capabilities
	Capabilities []string `json:"capabilities,omitempty"`

	// SieveVersion is the supported Sieve version
	SieveVersion string `json:"sieve_version,omitempty"`

	// Implementation identifies the server implementation
	Implementation string `json:"implementation,omitempty"`

	// StartTLSSupported indicates if the server supports STARTTLS
	StartTLSSupported bool `json:"starttls_supported"`

	// AuthMechanisms lists supported authentication mechanisms
	AuthMechanisms []string `json:"auth_mechanisms,omitempty"`

	// TLSLog contains the TLS handshake log if TLS was used
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`

	// StartTLSResponse is the server response to the STARTTLS command
	StartTLSResponse string `json:"starttls_response,omitempty"`

	// Per RFC 5804, the server must advertise capabilities after TLS connection establishment
	PostTLSCapabilities []string `json:"post_tls_capabilities,omitempty"`
}

// RegisterModule registers the ManageSieve module with zgrab2
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("managesieve", "ManageSieve Protocol", module.Description(), 4190, &module)
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
	return "Scan for Capabilities of ManageSieve servers (RFC 5804)"
}

// Validate validates the flags.
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the scanner with the given flags.
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

// InitPerSender initializes the scanner for each sender goroutine.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the scanner name.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the scanner trigger.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier.
func (scanner *Scanner) Protocol() string {
	return "managesieve"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// GetScanMetadata returns any metadata about the scan (implementing zgrab2.Scanner)
func (scanner *Scanner) GetScanMetadata() interface{} {
	return nil
}

// Scan performs the ManageSieve scan.
func (scanner *Scanner) Scan(ctx context.Context, dialerGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	l4Dialer := dialerGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, errors.New("L4 dialer is required in dialer group")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", addr)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	results := &ScanResults{}

	// Read initial banner
	banner, err := scanner.readResponse(conn, scanner.config.BannerTimeout)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("failed to read banner: %v", err)
	}

	results.Banner = banner
	if !scanner.isManageSieveResponse(banner) {
		return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("invalid ManageSieve banner: %s", banner)
	}

	// Send CAPABILITY command
	if cmdErr := scanner.sendCommand(conn, "CAPABILITY"); cmdErr != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("failed to send CAPABILITY: %v", cmdErr)
	}

	// Read capabilities response
	capResponse, err := scanner.readResponse(conn, scanner.config.BannerTimeout)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("failed to read capabilities: %v", err)
	}

	// Parse capabilities
	scanner.parseCapabilities(capResponse, results)

	// Attempt TLS negotiation, if supported
	if results.StartTLSSupported {
		// Send STARTTLS command
		if cmdErr := scanner.sendCommand(conn, "STARTTLS"); cmdErr != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("failed to send STARTTLS: %v", cmdErr)
		}

		// Get Server Reply
		results.StartTLSResponse, err = scanner.readResponse(conn, scanner.config.BannerTimeout)
		if err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("failed to read STARTTLS reply: %v", err)
		}
		results.StartTLSResponse = strings.ReplaceAll(results.StartTLSResponse, "\"", "") // Clean quotes

		// Initiate TLS Handshake
		tlsConn, err := dialerGroup.TLSWrapper(ctx, target, conn)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), results, fmt.Errorf("could not initiate a TLS connection with server that says it supports STARTTLS: %w", err)
		}
		results.TLSLog = tlsConn.GetLog()

		// After TLS handshake, read capabilities again
		// RFC 5804 Section 2.2 - "After the TLS layer is established, the server MUST re-issue the
		// capability results, followed by an OK response.  This is necessary to
		// protect against man-in-the-middle attacks that alter the capabilities
		// list prior to STARTTLS.  This capability result MUST NOT include the
		// STARTTLS capability."
		postTLSCapResponse, err := scanner.readResponse(tlsConn, scanner.config.BannerTimeout)
		if err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("failed to read post-TLS capabilities: %v", err)
		}
		postTLSCapResponse = strings.ReplaceAll(postTLSCapResponse, "\"", "")
		results.PostTLSCapabilities = strings.Split(postTLSCapResponse, "\n")
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}

// readResponse reads a complete response from the connection
func (scanner *Scanner) readResponse(conn net.Conn, readTimoeut time.Duration) (string, error) {
	// Set read timeout
	if deadlineErr := conn.SetReadDeadline(time.Now().Add(readTimoeut)); deadlineErr != nil {
		return "", deadlineErr
	}
	reader := bufio.NewReader(conn)
	var response strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		line = strings.TrimSpace(line)
		response.WriteString(line)

		// ManageSieve responses end with OK/NO/BYE or continue with more data
		if scanner.isCompleteResponse(line) {
			break
		}
		response.WriteString("\n")
	}

	return response.String(), nil
}

// sendCommand sends a command to the ManageSieve server
func (scanner *Scanner) sendCommand(conn net.Conn, command string) error {
	_, err := fmt.Fprintf(conn, "%s\r\n", command)
	return err
}

// isManageSieveResponse checks if the response looks like a ManageSieve response
func (scanner *Scanner) isManageSieveResponse(response string) bool {
	// ManageSieve responses typically start with "OK", "NO", "BYE", or contain capabilities
	patterns := []string{
		`^OK`,
		`^NO`,
		`^BYE`,
		`"IMPLEMENTATION"`,
		`"SIEVE"`,
		`"SASL"`,
		`"STARTTLS"`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, response); matched {
			return true
		}
	}

	return false
}

// isCompleteResponse checks if a line represents a complete response
func (scanner *Scanner) isCompleteResponse(line string) bool {
	// Check for status responses
	if strings.HasPrefix(line, "OK") ||
		strings.HasPrefix(line, "NO") ||
		strings.HasPrefix(line, "BYE") {
		return true
	}

	// Check for capability list ending
	if strings.Contains(line, "\"OK\"") {
		return true
	}

	return false
}

// parseCapabilities extracts capabilities from the server response
func (scanner *Scanner) parseCapabilities(response string, results *ScanResults) {
	lines := strings.Split(response, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Remove quotes
		capability := strings.ReplaceAll(line, "\"", "")
		results.Capabilities = append(results.Capabilities, capability)

		// Extract specific information
		switch {
		case strings.HasPrefix(capability, "VERSION"):
			results.SieveVersion = strings.TrimPrefix(capability, "VERSION ")
		case strings.HasPrefix(capability, "IMPLEMENTATION"):
			results.Implementation = strings.TrimPrefix(capability, "IMPLEMENTATION ")
		case capability == "STARTTLS":
			results.StartTLSSupported = true
		case strings.HasPrefix(capability, "SASL"):
			mechanisms := strings.TrimPrefix(capability, "SASL ")
			results.AuthMechanisms = strings.Split(mechanisms, " ")
		}
	}
}
