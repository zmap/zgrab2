package dahua_dvr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"

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
	_, err := zgrab2.AddCommand("dahua_dvr", "Dahua DVR", module.Description(), 1723, &module)
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
	Start           [32]byte
	Model           string //16
	Middle          [32]byte
	FirmwareVersion string // 16
	End             [32]byte
	SerialNumber    string // 16
	Banner          string
}

// Reading the response and filling in the structure
func (scanner *Scanner) readReply(data []byte) *ConnectionReply {

	//Clipping the last insignificant zeros in a string
	cutLastZero := func(b []byte) []byte {
		for i := len(b) - 1; i > 0; i-- {
			if b[i] != 0 {
				return b[:i+1]
			}
		}
		return make([]byte, 0)
	}

	reply := &ConnectionReply{}
	lenData := len(data)
	if lenData >= 32 {
		copy(reply.Start[:], data[:32])
		if lenData >= 48 {
			reply.Model = string(cutLastZero(data[32:48]))
			if lenData >= 80 {
				copy(reply.Middle[:], data[48:80])
				if lenData >= 96 {
					reply.FirmwareVersion = string(cutLastZero(data[80:96]))
					if lenData >= 128 {
						copy(reply.End[:], data[96:128])
						if lenData >= 144 {
							reply.SerialNumber = string(cutLastZero(data[128:144]))
						}
					}
				}
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
	if !(len(data) >= 32 && bytes.Equal(reply.Start[:3], []byte{0xb4, 0x00, 0x00}) && reply.Start[8] == byte(0x0b)) {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, fmt.Errorf("its not a dahua dvr")
	}

	return zgrab2.SCAN_SUCCESS, reply, nil
}
