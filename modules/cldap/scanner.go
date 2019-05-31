// Package cldap provides a zgrab2 module that scans for CLDAP servers.
// Default Port: 389 (UDP)
package cldap

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"encoding/base64"
	"io"
        "encoding/hex"
        ber "gopkg.in/asn1-ber.v1"
)

// Results is the struct that is returned to the zgrab2 framework from Scan()
type Results struct {
	IsCldap                  bool     `json:"is_cldap"`
	FullResponse             string   `json:"full_response"`
}

// Flags holds the command-line configuration for the cldap scan module.
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
	_, err := zgrab2.AddCommand("cldap", "cldap", "Probe for cldap", 389, &module)
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
	return "cldap"
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

var cldap_ddos_query []byte = CldapRecursionQuery()
var transaction_id int64 = ber.DecodePacket(cldap_ddos_query).Children[0].Value.(int64)

func CldapRecursionQuery() ([]byte) {
        // zmap/examples/udp-probes/ldap_389.pkt content
        // only change - 30840000002d020101 -> 30840000002d02013e
        // to make unique id(01 -> 3e)
        v, _ := hex.DecodeString("30840000002d02013e63840000002404000a01000a0100020100020100010100870b6f626a656374636c617373308400000000000a")
	return v
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	sock, err := target.OpenUDP(&scanner.config.BaseFlags, &scanner.config.UDPFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer sock.Close()
	// send query
	_, err = sock.Write(cldap_ddos_query)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	// get response
	buf := make([]byte, 16384) // most responses are about 4k
	n, err := io.ReadAtLeast(sock, buf, 1)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
        parsed_packet := ber.DecodePacket(buf)

        var is_cldap bool = false
        if parsed_packet != nil && len(parsed_packet.Children) > 0 {
                v, succ := parsed_packet.Children[0].Value.(int64)
                if succ && v == transaction_id {
                        is_cldap = true
                }
        }
	response_base64 := base64.StdEncoding.EncodeToString(buf[:n])

	return zgrab2.SCAN_SUCCESS, Results{is_cldap, response_base64}, nil
}
