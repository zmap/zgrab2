package pptp

import (
	"bytes"
	"encoding/binary"
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
	return "pptp"
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
	_, err := zgrab2.AddCommand("pptp", "PPTP", module.Description(), 1723, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *Module) Description() string {
	return "Сollect information on PPTP"
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

const MAGIC_COOKIE = 0x1A2B3C4D

type StartControlConnectionRequest struct {
	Length              uint16
	MsgType             uint16
	MagicCookie         uint32
	ControlMessageType  uint16
	Reserved0           uint16
	ProtocolVersion     uint16
	Reserved1           uint16
	FramingCapabilities uint32
	BearerCapabilities  uint32
	MaxChannels         uint16
	FirmwareRevision    uint16
	Hostname            [64]byte
	Vendor              [64]byte
}

func createStartControlConnectionRequest() *StartControlConnectionRequest {
	request := &StartControlConnectionRequest{
		Length:              156,
		MsgType:             1,
		MagicCookie:         MAGIC_COOKIE,
		ControlMessageType:  1,
		ProtocolVersion:     0x0100,
		FramingCapabilities: 0x1,
		BearerCapabilities:  0x1,
		FirmwareRevision:    0x1,
	}
	copy(request.Hostname[:], "Client")
	copy(request.Vendor[:], "Go")

	return request
}

type StartControlConnectionReply struct {
	Length              uint16
	MsgType             uint16
	MagicCookie         uint32
	ControlMessageType  uint16
	Reserved0           uint16
	ProtocolVersion     uint16
	ResultCode          uint8
	ErrorCode           uint8
	FramingCapabilities uint32
	BearerCapabilities  uint32
	MaxChannels         uint16
	FirmwareRevision    uint16
	Hostname            string
	Vendor              string
	Banner              string
}

// Reading the response and filling in the structure
func (scanner *Scanner) readReply(data []byte) *StartControlConnectionReply {

	//Clipping the last insignificant zeros in a string
	cutLastZero := func(b []byte) []byte {
		for i := len(b) - 1; i > 0; i-- {
			if b[i] != 0 {
				return b[:i+1]
			}
		}
		return make([]byte, 0)
	}

	reply := &StartControlConnectionReply{
		Length:              binary.BigEndian.Uint16(data[0:2]),
		MsgType:             binary.BigEndian.Uint16(data[2:4]),
		MagicCookie:         binary.BigEndian.Uint32(data[4:8]),
		ControlMessageType:  binary.BigEndian.Uint16(data[8:10]),
		ProtocolVersion:     binary.BigEndian.Uint16(data[12:14]),
		ResultCode:          uint8(data[14]) << 4,
		ErrorCode:           uint8(data[15]) << 4,
		FramingCapabilities: binary.BigEndian.Uint32(data[16:20]),
		BearerCapabilities:  binary.BigEndian.Uint32(data[20:24]),
		MaxChannels:         binary.BigEndian.Uint16(data[24:26]),
		FirmwareRevision:    binary.BigEndian.Uint16(data[26:28]),
		Hostname:            string(cutLastZero(data[28:92])),
		Vendor:              string(cutLastZero(data[92:156])),
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

	request := createStartControlConnectionRequest()
	var buffer bytes.Buffer
	if err := binary.Write(&buffer, binary.BigEndian, request); err != nil {
		fmt.Printf("Failed to encode request: %v\n", err)
		os.Exit(1)
	}
	conn.Write(buffer.Bytes())

	data, err := zgrab2.ReadAvailable(conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	reply := scanner.readReply(data)
	if reply.MagicCookie != MAGIC_COOKIE {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, fmt.Errorf("magic cookie is not equal")
	}

	return zgrab2.SCAN_SUCCESS, reply, nil
}
