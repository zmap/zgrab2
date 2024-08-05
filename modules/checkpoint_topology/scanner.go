package checkpointtopology

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

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
	return "checkpoint_topology"
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return ""
}

// Validate flags
func (f *Flags) Validate(args []string) (err error) {
	return nil
}

// RegisterModule registers this module in zgrab2
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("checkpoint_topology", "checkpoint_topology", module.Description(), 2000, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *Module) Description() string {
	return "Сollect information on checkpoint_topology"
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

type StartControlConnectionReply struct {
	Vendor string
	Banner string
}

// Reading the response and filling in the structure
func (scanner *Scanner) readReply(data []byte) *StartControlConnectionReply {

	reply := &StartControlConnectionReply{}

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

	conn.Write([]byte("\x51\x00\x00\x00\x00\x00\x00\x21"))

	data, err := zgrab2.ReadAvailable(conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	reply := scanner.readReply(data)
	if !bytes.Equal(data, []byte("Y\x00\x00\x00")) {
		return zgrab2.SCAN_UNKNOWN_ERROR, reply, fmt.Errorf("banner not equal")
	}

	return zgrab2.SCAN_SUCCESS, reply, nil
}
