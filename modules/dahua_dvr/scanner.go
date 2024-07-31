package dahua_dvr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags
	Hex bool `short:"x" long:"hex" description:"Оutputs as a byte sequence or conversion to a string"`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// GetName returns the configured name for the Scanner.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

// Init initializes the Scanner instance with the flags from the command
// line.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	return nil
}

// InitPerSender does nothing in this module.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// Protocol returns the protocol identifer for the scanner.
func (s *Scanner) Protocol() string {
	return "dahua_dvr"
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return ""
}

// Validate flags
func (f *Flags) Validate(args []string) (err error) {
	return nil
}

// RegisterModule registers the ftp zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("dahua_dvr", "Dahua DVR", module.Description(), 37777, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *Module) Description() string {
	return "Сollect information on Dahua DVR"
}

// NewFlags returns the default flags object to be filled in with the
// command-line arguments.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

type ConnectionReply struct {
	/* 	Start           [32]byte
	   	Model           string //16
	   	Middle          [32]byte
	   	FirmwareVersion string // 16
	   	End             [32]byte
	   	SerialNumber    string // 16 */
	Model           string
	FirmwareVersion string
	SerialNumber    string
	Length          int
	Banner          string
}

// Reading the response and filling in the structure
func (scanner *Scanner) readReply(data []byte) *ConnectionReply {

	strData := string(data)
	re, _ := regexp.Compile(`[A-Za-z\d-\./\(\)]{2,20}`)
	res := re.FindAllString(strData, -1)
	lenRes := len(res)
	reply := &ConnectionReply{
		Length: len(data),
	}

	if lenRes >= 1 {
		reply.Model = res[0]
		if lenRes >= 2 {
			reply.FirmwareVersion = res[1]
			if lenRes >= 3 {
				reply.SerialNumber = res[2]
			}
		}
	}

	if scanner.config.Hex {
		reply.Banner = hex.EncodeToString(data)
	} else {
		reply.Banner = string(data)
	}

	return reply
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {

	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error opening connection: %w", err)
	}
	defer conn.Close()

	request, err := hex.DecodeString("a4000000000000000b0000000000000000000000000000000000000000000000a400000000000000080000000000000000000000000000000000000000000000a400000000000000070000000000000000000000000000000000000000000000")
	if err != nil {
		fmt.Printf("Failed to encode request: %v\n", err)
		os.Exit(1)
	}
	conn.Write(request)

	data, err := zgrab2.ReadAvailable(conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	reply := scanner.readReply(data)
	//if !(len(data) >= 32 && bytes.Equal(reply.Start[:3], []byte{0xb4, 0x00, 0x00}) && reply.Start[8] == byte(0x0b)) {
	if !(bytes.Equal(data[:3], []byte{0xb4, 0x00, 0x00}) && data[8] == byte(0x0b)) {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, fmt.Errorf("its not a dahua dvr")
	}

	return zgrab2.SCAN_SUCCESS, reply, nil
}
