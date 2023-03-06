// Package tcp provides a zgrab2 module that scans for tcp connections.
// Default Port: 22 (TCP)
// USAGE:
// ./cmd/zgrab2/zgrab2 tcp  --senders 200 --rw-timeout 2 --input-file //Users/ibondar/Downloads/network_telescope/list_61000 --output-file 61000_2 --hex-probe 0300002f2ae00000000000436f6f6b69653a206d737473686173683d41646d696e697374720d0a0100080003000000
package tcp

import (
    log "github.com/sirupsen/logrus"
    "github.com/packetloop/zgrab2"
    "encoding/hex"
)

type Results struct {
    FullResponse             string   `json:"full_response"`
}

// Flags holds the command-line configuration for the scan module.
// Populated by the framework.
type Flags struct {
    zgrab2.BaseFlags
    Probe    string `long:"hex-probe" default:"" description:"Hex-encoded probe to send to the server."`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
    config *Flags
    probe  []byte
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
    var module Module
    _, err := zgrab2.AddCommand("tcp", "tcp", "Probe for tcp", 22, &module)
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
    return "tcp"
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
    return scanner.config.Port
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
    conn, err := target.Open(&scanner.config.BaseFlags)
    data, _ := hex.DecodeString(scanner.config.Probe)
    if err != nil {
        return zgrab2.TryGetScanStatus(err), nil, err
    }
    defer conn.Close()
    _, _ = conn.Write(data)
    var ret []byte
    ret, _ = zgrab2.ReadAvailable(conn)
    return zgrab2.SCAN_SUCCESS, Results{hex.EncodeToString(ret)}, nil
}
