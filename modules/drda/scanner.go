// Package drda provides a zgrab2 module that scans for DRDA database servers,
// most commonly IBM DB2 (DRDA is also spoken by Apache Derby and Informix).
// Default port: 50000 (TCP).
//
// It sends a DRDA EXCSAT ("Exchange Server Attributes") request and parses the
// EXCSATRD reply, extracting server-identifying attributes (server class /
// platform, instance name, product release level and external name). These are
// the same attributes surfaced by Shodan and nmap's drda-info script.
package drda

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the drda scan module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
}

// Results is the output of the drda scan module.
type Results struct {
	// ServerClass is the DRDA SRVCLSNM attribute, describing the server
	// platform, e.g. "QDB2/NT64".
	ServerClass string `json:"server_class,omitempty"`
	// InstanceName is the DRDA SRVNAM attribute, e.g. "DB2".
	InstanceName string `json:"instance_name,omitempty"`
	// ReleaseLevel is the raw DRDA SRVRLSLV attribute, e.g. "SQL11013".
	ReleaseLevel string `json:"release_level,omitempty"`
	// Version is the human-readable version derived from ReleaseLevel, e.g.
	// "11.01.3".
	Version string `json:"version,omitempty"`
	// ExternalName is the DRDA EXTNAM attribute.
	ExternalName string `json:"external_name,omitempty"`
	// ProductID is the DRDA PRDID attribute, when present.
	ProductID string `json:"product_id,omitempty"`
	// Raw is the hex-encoded EXCSATRD response, included when --verbose is set.
	Raw string `json:"raw,omitempty"`
}

// Module implements the zgrab2.Module interface.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"drda",
		"Probe for DRDA database servers (IBM DB2, Derby, Informix)",
		"Send a DRDA EXCSAT request and parse the EXCSATRD reply for server attributes",
		50000,
	)
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// Validate checks that the flags are valid. Always succeeds.
func (flags Flags) Validate(_ []string) error {
	return nil
}

// Init initializes the Scanner.
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

// readDDM reads a single length-prefixed DRDA DDM message from conn.
func readDDM(conn io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("could not read DRDA length prefix: %w", err)
	}
	length := int(binary.BigEndian.Uint16(header))
	if length < ddmHeaderLen {
		return nil, fmt.Errorf("invalid DRDA message length %d", length)
	}
	buf := make([]byte, length)
	copy(buf, header)
	if _, err := io.ReadFull(conn, buf[2:]); err != nil {
		return nil, fmt.Errorf("could not read DRDA message body: %w", err)
	}
	return buf, nil
}

// Scan connects to the target (default port 50000), sends a DRDA EXCSAT request,
// and parses the EXCSATRD reply.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not dial target %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	if _, err = conn.Write(buildEXCSAT()); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not send EXCSAT to %s: %w", target.String(), err)
	}

	data, err := readDDM(conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	attrs, ok := parseEXCSATRD(data)
	if !ok {
		if scanner.config.Verbose {
			log.Debugf("drda: response was not a valid EXCSATRD: %s", hex.EncodeToString(data))
		}
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("response from %s was not a DRDA EXCSATRD", target.String())
	}

	results := &Results{
		ServerClass:  attrs.serverClass,
		InstanceName: attrs.serverName,
		ReleaseLevel: attrs.releaseLevel,
		Version:      versionFromReleaseLevel(attrs.releaseLevel),
		ExternalName: attrs.externalName,
		ProductID:    attrs.productID,
	}
	if scanner.config.Verbose {
		results.Raw = hex.EncodeToString(data)
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}
