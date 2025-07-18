// Ref: https://github.com/salesforce/jarm
// https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a?gi=4dd05e2277e4
package jarm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hdm/jarm-go"
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	MaxTries         int `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config            *Flags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

type Results struct {
	Fingerprint string `json:"fingerprint"`
}

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("jarm", "TLS server fingerprinting (JARM)", module.Description(), 443, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() any {
	return new(Flags)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Send TLS requiests and generate a JARM fingerprint"
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "jarm"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(_ []string) error {
	return nil
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	// Stores raw hashes returned from parsing each protocols Hello message
	rawhashes := []string{}

	// Loop through each Probe type
	for _, probe := range jarm.GetProbes(target.Host(), int(scanner.GetPort())) {
		if zgrab2.HasCtxExpired(ctx) {
			return zgrab2.SCAN_IO_TIMEOUT, nil, errors.New("scan timed out")
		}
		var (
			conn net.Conn
			err  error
			ret  []byte
		)
		conn, err = dialGroup.Dial(ctx, target)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not dial target %s: %w", target.String(), err)
		}

		_, err = conn.Write(jarm.BuildProbe(probe))
		if err != nil {
			rawhashes = append(rawhashes, "")
			zgrab2.CloseConnAndHandleError(conn)
			continue
		}

		ret, _ = zgrab2.ReadAvailableWithOptions(conn, 1484, 500*time.Millisecond, 0, 1484)

		ans, err := jarm.ParseServerHello(ret, probe)
		if err != nil {
			rawhashes = append(rawhashes, "")
			zgrab2.CloseConnAndHandleError(conn)
			continue
		}

		rawhashes = append(rawhashes, ans)
		zgrab2.CloseConnAndHandleError(conn)
	}

	var fingerprint = jarm.RawHashToFuzzyHash(strings.Join(rawhashes, ","))

	if fingerprint == "00000000000000000000000000000000000000000000000000000000000000" {
		return zgrab2.SCAN_APPLICATION_ERROR, nil, errors.New("unable to calculate hashes from server")
	}

	return zgrab2.SCAN_SUCCESS, &Results{
		Fingerprint: fingerprint,
	}, nil
}
