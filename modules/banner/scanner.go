// Package banner provides simple banner grab and matching implementation of the zgrab2.Module.
// It sends a customizble probe (default to "\n") and filters the results based on custom regexp (--pattern)

package banner

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	ReadTimeout int    `long:"read-timeout" default:"10" description:"Read timeout in milliseconds"`
	BufferSize  int    `long:"buffer-size" default:"8209" description:"Read buffer size in bytes"`
	MaxReadSize int    `long:"max-read-size" default:"512" description:"Maximum amount of data to read in KiB (1024 bytes)"`
	Probe       string `long:"probe" default:"\\n" description:"Probe to send to the server. Use triple slashes to escape, for example \\\\\\n is literal \\n. Mutually exclusive with --probe-file."`
	ProbeFile   string `long:"probe-file" description:"Read probe from file as byte array (hex). Mutually exclusive with --probe."`
	Pattern     string `long:"pattern" description:"Pattern to match, must be valid regexp."`
	UseTLS      bool   `long:"tls" description:"Sends probe with TLS connection. Loads TLS module command options."`
	MaxTries    int    `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up. Includes making TLS connection if enabled."`
	Hex         bool   `long:"hex" description:"Store banner value in hex. Mutually exclusive with --base64."`
	Base64      bool   `long:"base64" description:"Store banner value in base64. Mutually exclusive with --hex."`
	MD5         bool   `long:"md5" description:"Calculate MD5 hash of banner value."`
	SHA1        bool   `long:"sha1" description:"Calculate SHA1 hash of banner value."`
	SHA256      bool   `long:"sha256" description:"Calculate SHA256 hash of banner value."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config            *Flags
	regex             *regexp.Regexp
	probe             []byte
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
	Banner string         `json:"banner,omitempty"`
	Length int            `json:"length,omitempty"`
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
	MD5    string         `json:"md5,omitempty"`
	SHA1   string         `json:"sha1,omitempty"`
	SHA256 string         `json:"sha256,omitempty"`
}

var ErrNoMatch = errors.New("pattern did not match")

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var m Module
	_, err := zgrab2.AddCommand("banner", "Grabs the server's response to an arbitrary probe with optional regex matching", m.Description(), 80, &m)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() any {
	return new(Flags)
}

// GetName returns the Scanner name defined in the Flags.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (s *Scanner) Protocol() string {
	return "banner"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// InitPerSender initializes the scanner for a given sender.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(_ []string) error {
	if f.Probe != "\\n" && f.ProbeFile != "" {
		log.Fatal("Cannot set both --probe and --probe-file")
		return zgrab2.ErrInvalidArguments
	}
	return nil
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Fetch a raw banner by sending a static probe and checking the result against an optional regular expression"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	var err error
	f, _ := flags.(*Flags)
	s.config = f
	if s.config.Pattern != "" {
		s.regex = regexp.MustCompile(s.config.Pattern)
	}
	if len(f.ProbeFile) != 0 {
		s.probe, err = os.ReadFile(f.ProbeFile)
		if err != nil {
			log.Fatal("Failed to open probe file")
			return zgrab2.ErrInvalidArguments
		}
	} else {
		strProbe, err := strconv.Unquote(fmt.Sprintf(`"%s"`, s.config.Probe))
		if err != nil {
			panic("Probe error")
		}
		s.probe = []byte(strProbe)
	}
	s.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      f.UseTLS,
	}
	if f.UseTLS {
		s.dialerGroupConfig.TLSFlags = &f.TLSFlags
	}
	return nil
}

func (s *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	var (
		conn    net.Conn
		err     error
		readErr error
		results Results
	)

	for try := 0; try < s.config.MaxTries; try++ {
		conn, err = dialGroup.Dial(ctx, target)
		if err != nil {
			continue // try again
		}
		break
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("failed to connect to %v: %w", target.String(), err)
	}
	defer func() {
		// attempt to collect TLS Log
		if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok {
			results.TLSLog = tlsConn.GetLog()
		}
		// cleanup our connection
		zgrab2.CloseConnAndHandleError(conn)
	}()

	var data []byte

	for try := 0; try < s.config.MaxTries; try++ {
		_, err = conn.Write(s.probe)
		data, readErr = zgrab2.ReadAvailableWithOptions(conn,
			s.config.BufferSize,
			time.Duration(s.config.ReadTimeout)*time.Millisecond,
			0,
			s.config.MaxReadSize*1024)
		if err != nil {
			continue
		}
		if readErr != io.EOF && readErr != nil {
			continue
		}
		break
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if readErr != io.EOF && readErr != nil {
		return zgrab2.TryGetScanStatus(readErr), nil, readErr
	}

	if s.config.Hex {
		results.Banner = hex.EncodeToString(data)
	} else if s.config.Base64 {
		results.Banner = base64.StdEncoding.EncodeToString(data)
	} else {
		results.Banner = string(data)
	}
	results.Length = len(data)

	if len(data) > 0 {
		if s.config.MD5 {
			digest := md5.Sum(data)
			results.MD5 = hex.EncodeToString(digest[:])
		}
		if s.config.SHA1 {
			digest := sha1.Sum(data)
			results.SHA1 = hex.EncodeToString(digest[:])
		}
		if s.config.SHA256 {
			digest := sha256.Sum256(data)
			results.SHA256 = hex.EncodeToString(digest[:])
		}
	}
	if s.regex == nil {
		return zgrab2.SCAN_SUCCESS, &results, nil
	}
	if s.regex.Match(data) {
		return zgrab2.SCAN_SUCCESS, &results, nil
	}

	return zgrab2.SCAN_PROTOCOL_ERROR, &results, ErrNoMatch
}
