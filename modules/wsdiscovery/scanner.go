// Package wsdiscovery provides a zgrab2 module that scans for vulnerable WS-Discovery servers.
// Default Port: 3702 (UDP)
package wsdiscovery

import (
    log "github.com/sirupsen/logrus"
    "github.com/zmap/zgrab2"
    "encoding/base64"
    "io"
    "encoding/hex"
    "net"
)

/*
Scan results for different 
wsdiscovery_capaa 41914 REQUEST: 3caa3e00  <ª>
wsdiscovery_capcol 45423 REQUEST: 3c3a3e00 <:>
wsdiscovery_capdot 44205 REQUEST: 3c2e3e00 <.>
wsdiscovery_empty 24287  REQUEST:
wsdiscovery_col 15785  REQUEST: 3a00  :\0
wsdiscovery_empty00 4301  REQUEST: 00 \0
wsdiscovery_r 2913 REQUEST: 0d00  \r\0

But ip sets for all <*> requests are similar. So we scan for <.>, then empty packet, then column and zero byte request.
*/

var requests := [4]string{"3c2e3e00", "", "3a00", "00"} // <.>, empty packet, column, zero byte
var min_vulnerable_size int = 200 // 200 is about 4x amplification, typical non-amplifier is about half of that

// Results is the struct that is returned to the zgrab2 framework from Scan()
type Results struct {
    IsVulnerable             bool     `json:"is_vulnerable"`
    FullResponse             string   `json:"full_response"`
}

// Flags holds the command-line configuration for the WS-Discovery scan module.
// Populated by the framework.
type Flags struct {
    zgrab2.BaseFlags
    zgrab2.UDPFlags
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
    config *Flags
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
    var module Module
    _, err := zgrab2.AddCommand("wsdiscovery", "wsdiscovery", "Probe for WS-Discovery", 3702, &module)
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

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
    return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
    return ""
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
    f, _ := flags.(*Flags)
    scanner.config = f
    return nil
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
    return nil
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
    return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
    return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
    return "wsdiscovery"
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
    return scanner.config.Port
}

func IsTargetVulnerable(hexstr string, sock net.Conn) (bool, string, error) {
	data, _ := hex.DecodeString(hexstr)
    _, err := sock.Write([]byte(data))
    if err != nil {
        return false, "", err
    }
    // get response
    buf := make([]byte, 16384) 
    n, err := io.ReadAtLeast(sock, buf, 1)
    if err != nil {
        return false, "", err
    }
    return (n > min_vulnerable_size), base64.StdEncoding.EncodeToString(buf[:n]), nil
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
    sock, err := target.OpenUDP(&scanner.config.BaseFlags, &scanner.config.UDPFlags)
    if err != nil {
        return zgrab2.TryGetScanStatus(err), nil, err
    }
    defer sock.Close()

    for _, data := range requests { // we run requests sequentally, since parralell requests can interfere with each other
    	isVulnerable, response, _ := IsTargetVulnerable(data, sock)
        if isVulnerable {
            return zgrab2.SCAN_SUCCESS, Results{isVulnerable, response}, nil
        }
    }

    return zgrab2.SCAN_SUCCESS, Results{false, ""}, nil
}
