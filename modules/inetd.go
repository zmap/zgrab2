package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Module names
const (
	svcEcho    string = "echo"
	svcDaytime        = "daytime"
	svcChargen        = "chargen"
	svcTime           = "time"
)

// Mapping of default ports to the corresponding service id
var portToService map[uint]string = map[uint]string{
	7:  svcEcho,
	13: svcDaytime,
	19: svcChargen,
	37: svcTime,
}

var serviceToTestPackets map[string][][]byte = map[string][][]byte{
	svcEcho: [][]byte{
		[]byte{1},
		[]byte{0x31},
		[]byte{0x32, 0x33, 0x34, 0x0A, 0x0D},
		make([]byte, 512),
	},
	svcDaytime: [][]byte{[]byte{}},
	svcChargen: [][]byte{
		[]byte{1},
		[]byte{0x31},
		[]byte{0x32, 0x33, 0x34, 0x0A, 0x0D},
		make([]byte, 512),
	},
	svcTime: [][]byte{[]byte{}},
}

// The data returned on successful detection. Returns the largest response from the server.
type InetdResults struct {
	OutputSize *uint32 `json:"output_size,omitempty"`
	OutputData *string `json:"output_data,omitempty"`
}

// Command line flags. Specifies the service to check for, along with optional UDP configuration.
type InetdFlags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags
	UDP     bool `long:"udp" description:"Use the UDP versions of the protocols"`
	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// zgrab2 module implementation
type InetdModule struct {
	Service string
	Checker checker
}

// State for individual scan
type InetdScanner struct {
	module *InetdModule
	config *InetdFlags
}

type InetdScan struct {
	scanner       *InetdScanner
	totalSent     []byte
	totalReceived []byte
}

// Set up the modules
func init() {
	for port, service := range portToService {
		_, err := zgrab2.AddCommand(service, service, "Scan for inetd modules", int(port), &InetdModule{Service: service, Checker: serviceMap[service]})
		if err != nil {
			log.Fatal(err)
		}
	}
}

func (self *InetdModule) NewFlags() interface{} {
	return new(InetdFlags)
}

func (self *InetdModule) NewScanner() zgrab2.Scanner {
	return &InetdScanner{module: self}
}

func (self *InetdFlags) Validate(args []string) error {
	return nil
}

func (self *InetdFlags) Help() string {
	return ""
}

func (self *InetdScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*InetdFlags)
	self.config = f
	return nil
}

func (self *InetdScanner) InitPerSender(senderID int) error {
	return nil
}

func (self *InetdScanner) GetName() string {
	return self.config.Name
}

func (self *InetdScanner) GetPort() uint {
	return self.config.Port
}

// hasNonASCII() checks if buf has any non-printable-ASCII characters, except those in except
func hasNonASCII(buf []byte, except string) bool {
	str := string(buf)
	for _, v := range str {
		if (v < 0x20 || v >= 0x7f) && !strings.ContainsRune(except, v) {
			return true
		}
	}
	return false
}

// checkers check if the outPacket and inPacket are consistent with the given service
type checker func(self *InetdScan, outPacket, inPacket []byte) bool

// Checker for the Daytime protocol (RFC867)
func (self *InetdScan) looksLikeDaytime(outbuf, buf []byte) bool {
	// From RFC867:
	//	- There is no specific syntax for the daytime.
	//  - It is recommended that it be limited to the ASCII printing characters, space, carriage return, and line feed.
	//  - The daytime should be just one line.
	if len(buf) < 8 {
		// arbitrary cutoff; but anything shorter than HHMMSS is definitely not a daytime.
		return false
	}
	if hasNonASCII(buf, "\r\n") {
		return false
	}
	return true
}

// Checker for the Echo protocol
func (self *InetdScan) looksLikeEcho(outbuf, inbuf []byte) bool {
	if len(outbuf) != len(inbuf) {
		return false
	}
	return bytes.Compare(outbuf, inbuf) == 0
}

// Checker for the Time protocol (RFC868)
func (self *InetdScan) looksLikeTime(outPacket, inPacket []byte) bool {
	// RFC868 -- returns a 32-bit number, "number of seconds since 00:00 (midnight) 1 January 1900 GMT"
	if len(inPacket) != 4 {
		return false
	}
	// Network byte order = big endian
	// Though the RFC mentions negative times, a signed 32-bit number would only take us through 1968 (as opposed to the 2036 mentioned in the text)
	secsSince1900 := binary.BigEndian.Uint32(inPacket)
	timeBase := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	when := timeBase.Add(time.Duration(secsSince1900) * time.Second)
	// Huge window -- allow any dates within a 4 week window surrounding the present
	earliest := time.Now().AddDate(0, 0, -14)
	latest := time.Now().AddDate(0, 0, 14)
	return when.After(earliest) && when.Before(latest)
}

// Checker for the Chargen protocol (RFC864)
func (self *InetdScan) looksLikeChargen(outPacket, inPacket []byte) bool {
	/*
		From RFC864:

		Data Syntax

		   The data may be anything.  It is recommended that a recognizable
		   pattern be used in tha data.

		      One popular pattern is 72 chraracter lines of the ASCII printing
		      characters.  There are 95 printing characters in the ASCII
		      character set.  Sort the characters into an ordered sequence and
		      number the characters from 0 through 94.  Think of the sequence as
		      a ring so that character number 0 follows character number 94.  On
		      the first line (line 0) put the characters numbered 0 through 71.
		      On the next line (line 1) put the characters numbered 1 through
		      72.  And so on.  On line N, put characters (0+N mod 95) through
		      (71+N mod 95).  End each line with carriage return and line feed.
	*/
	// Obviously "the data may be anything" means that we can have false negatives.
	// So, we just check something similar to the "popular pattern".

	if hasNonASCII(inPacket, "\r\n\t") {
		return false
	}
	str := string(inPacket)
	if !self.scanner.config.UDP {
		// For TCP, use the entire output
		str = string(self.totalReceived)
	}
	str = strings.Trim(str, "\r\n")
	lines := strings.Split(str, "\n")

	// Arbitrary cutoff
	if len(lines[0]) < 16 {
		return false
	}

	// Lines all the same length, except perhaps the last line
	for n := 1; n < len(lines)-1; n++ {
		line := lines[n]
		if len(line) != len(lines[n-1]) {
			return false
		}
	}

	// Characters increment throughout the line, mod some value
	for _, line := range lines[0:] {
		// Number of discontinuities in this line
		jumps := 0
		line = strings.Trim(line, "\r\n")
		for i := 1; i < len(line); i++ {
			prev := line[i-1]
			ch := line[i]
			if ch != prev+1 {
				jumps++
				// If it jumps forward, it's not mod
				if ch >= prev {
					return false
				}
				// If there was more than one jump, it's probably not chargen
				if jumps > 1 {
					return false
				}
			}
		}
	}
	return true
}

// Map of service name to the checker for that service
var serviceMap map[string]checker = map[string]checker{
	svcChargen: (*InetdScan).looksLikeChargen,
	svcTime:    (*InetdScan).looksLikeTime,
	svcDaytime: (*InetdScan).looksLikeDaytime,
	svcEcho:    (*InetdScan).looksLikeEcho,
}

// InetdScanner.open() connects to the target using the configured flags (tcp, or udp if --udp is set)
func (self *InetdScanner) open(t *zgrab2.ScanTarget) (net.Conn, error) {
	if self.config.UDP {
		return t.OpenUDP(&self.config.BaseFlags, &self.config.UDPFlags)
	} else {
		return t.Open(&self.config.BaseFlags)
	}
}

// Scan sends a series of packets to the service, and reads the response, then checks the input/output pair against the service's checker.
func (self *InetdScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan := &InetdScan{scanner: self}
	sock, err := self.open(&t)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	result := &InetdResults{}
	testPackets := serviceToTestPackets[self.module.Service]
	readBuf := make([]byte, 8192)
	for _, packet := range testPackets {
		n, err := sock.Write(packet)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		if n != len(packet) {
			return zgrab2.SCAN_UNKNOWN_ERROR, result, nil
		}
		scan.totalSent = append(scan.totalSent, packet...)
		n, err = sock.Read(readBuf)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		response := readBuf[0:n]
		scan.totalReceived = append(scan.totalReceived, response...)

		if result.OutputSize == nil || uint32(n) > *result.OutputSize {
			u32 := uint32(n)
			result.OutputSize = &u32
			temp := string(response)
			result.OutputData = &temp
		}
		if !self.module.Checker(scan, packet, response) {
			return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("Response from %s did not match expected format for %s (got %s)", hex.EncodeToString(packet), self.module.Service, hex.EncodeToString(response))
		}
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}
