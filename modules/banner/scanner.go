// Package banner provides simple banner grab and matching implementation of the zgrab2.Module.
// It sends a customizble probe (default to "\n") and filters the results based on custom regexp (--pattern)

package banner

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strconv"

	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	Probe     string `long:"probe" default:"\\n" description:"Probe to send to the server. Use triple slashes to escape, for example \\\\\\n is literal \\n. Mutually exclusive with --probe-file."`
	ProbeFile string `long:"probe-file" description:"Read probe from file as byte array (hex). Mutually exclusive with --probe."`
	Pattern   string `long:"pattern" description:"Pattern to match, must be valid regexp."`
	UseTLS    bool   `long:"tls" description:"Sends probe with TLS connection. Loads TLS module command options."`
	MaxTries  int    `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up. Includes making TLS connection if enabled."`
	Hex       bool   `long:"hex" description:"Store banner value in hex. Mutually exclusive with --base64."`
	Base64    bool   `long:"base64" description:"Store banner value in base64. Mutually exclusive with --hex."`
	MD5       bool   `long:"md5" description:"Calculate MD5 hash of banner value."`
	SHA1      bool   `long:"sha1" description:"Calculate SHA1 hash of banner value."`
	SHA256    bool   `long:"sha256" description:"Calculate SHA256 hash of banner value."`
	zgrab2.TLSFlags
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	regex  *regexp.Regexp
	probe  []byte
}

// ScanResults instances are returned by the module's Scan function.
type Results struct {
	Banner string         `json:"banner,omitempty"`
	Length int            `json:"length,omitempty"`
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
	MD5    string         `json:"md5,omitempty"`
	SHA1   string         `json:"sha1,omitempty"`
	SHA256 string         `json:"sha25,omitempty"`
}

var NoMatchError = errors.New("pattern did not match")

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var m Module
	_, err := zgrab2.AddCommand("banner", "Banner", m.Description(), 80, &m)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
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

// InitPerSender initializes the scanner for a given sender.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	if f.Probe != "\\n" && f.ProbeFile != "" {
		log.Fatal("Cannot set both --probe and --probe-file")
		return zgrab2.ErrInvalidArguments
	}
	return nil
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Fetch a raw banner by sending a static probe and checking the result against a regular expression"
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
		s.probe, err = ioutil.ReadFile(f.ProbeFile)
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
	return nil
}

func (s *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	var (
		conn    net.Conn
		tlsConn *zgrab2.TLSConnection
		err     error
		readErr error
	)

	for try := 0; try < s.config.MaxTries; try++ {
		conn, err = target.Open(&s.config.BaseFlags)
		if err != nil {
			continue
		}
		if s.config.UseTLS {
			tlsConn, err = s.config.TLSFlags.GetTLSConnection(conn)
			if err != nil {
				continue
			}
			if err = tlsConn.Handshake(); err != nil {
				continue
			}
			conn = tlsConn
		}
		break
	}

	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	var data []byte

	for try := 0; try < s.config.MaxTries; try++ {
		_, err = conn.Write(s.probe)
		data, readErr = zgrab2.ReadAvailable(conn)
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

	var results Results

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
	if tlsConn != nil {
		results.TLSLog = tlsConn.GetLog()
	}
	if s.regex == nil {
		return zgrab2.SCAN_SUCCESS, &results, nil
	}
	if s.regex.Match(data) {
		return zgrab2.SCAN_SUCCESS, &results, nil
	}

	return zgrab2.SCAN_PROTOCOL_ERROR, &results, NoMatchError
}
