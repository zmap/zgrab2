// Package dns provides a zgrab2 module that scans for DNS services with enabled dns-recursion.
// Default Port: 53 (UDP)
package dns

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"encoding/base64"
	"encoding/binary"
	"io"
)

// Results is the struct that is returned to the zgrab2 framework from Scan()
type Results struct {
	IsDns                    bool     `json:"is_dns"`
	DnsRecursionEnabled      bool     `json:"dns_recursion_enabled"`
	FullResponse             string   `json:"full_response"`
}

// Flags holds the command-line configuration for the dns scan module.
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
	_, err := zgrab2.AddCommand("dns", "dns", "Probe for dns", 53, &module)
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
	return "dns"
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

var transaction_id uint16 = 0xdead
var dns_recursion_query []byte = DnsRecursionQuery()

// based on https://svn.nmap.org/nmap/scripts/dns-recursion.nse
func DnsRecursionQuery() ([]byte) {
	domain := "\x03www\x09wikipedia\x03org\x00"			// www.wikipedia.org - encoded and null-terminated
	ret := make([]byte, 8*2 + len(domain))
	binary.BigEndian.PutUint16(ret[ 0: 2], transaction_id)		// Transaction-ID
	binary.BigEndian.PutUint16(ret[ 2: 4], 0x0100)			// flags (recursion desired)
	binary.BigEndian.PutUint16(ret[ 4: 6], 0x0001)			// 1 question
	binary.BigEndian.PutUint16(ret[ 6: 8], 0x0000)			// 0 answers
	binary.BigEndian.PutUint16(ret[ 8:10], 0x0000)			// 0 authority
	binary.BigEndian.PutUint16(ret[10:12], 0x0000)			// 0 additional
	copy(ret[12:], domain)						// domain
	ret_end := ret[6*2 + len(domain):]
	binary.BigEndian.PutUint16(ret_end[0:2], 0x0001)		// type A
	binary.BigEndian.PutUint16(ret_end[2:4], 0x0001)		// class IN
	return ret
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	sock, err := target.OpenUDP(&scanner.config.BaseFlags, &scanner.config.UDPFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer sock.Close()
	// send query
	_, err = sock.Write(dns_recursion_query)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	// get response
	buf := make([]byte, 256)
	n, err := io.ReadAtLeast(sock, buf, 1)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	// process response
	if n < 12 { // 12 is header size, see rfc1035 4.1.1
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	is_dns := binary.BigEndian.Uint16(buf[0:2]) == transaction_id
	// QR == 1 and RA == 1 and RCODE == 0 - is response and recursion available and no error, see rfc1035 4.1.1(page 26)
	dns_recursion_on := (buf[2] & 0x80 == 0x80) && (buf[3] & 0x85 == 0x80)
	response_base64 := base64.StdEncoding.EncodeToString(buf[:n])

	return zgrab2.SCAN_SUCCESS, Results{is_dns, dns_recursion_on, response_base64}, nil
}
