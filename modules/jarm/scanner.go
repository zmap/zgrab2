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

	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the jarm module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	MaxTries         int `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
	*zgrab2.BaseModule
}

func NewModule() *Module {
	return &Module{
		BaseModule: zgrab2.NewBaseModule("jarm", "TLS server fingerprinting (JARM)", "Send TLS requests and generate a JARM fingerprint", 443),
	}
}

func (m *Module) NewFlags() any { return new(Flags) }

func (m *Module) NewScanner() zgrab2.Scanner {
	return &Scanner{BaseScanner: zgrab2.NewBaseScanner(m.Protocol())}
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	*zgrab2.BaseScanner
	config *Flags
}

type Results struct {
	Fingerprint string `json:"fingerprint"`
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(_ []string) error {
	return nil
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
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
