package modules

import (
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type ChargenResults struct {
	OutputSize *uint32 `json:"output_size,omitempty"`
	OutputData *string `json:"output_data,omitempty"`
}

type ChargenFlags struct {
	zgrab2.BaseFlags
	Verbose   bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	LocalAddr string `long:"local-addr" description:"Set an explicit local address, in the format ip:port (e.g. 0.0.0.0:55555)"`
}

type ChargenModule struct {
}

type ChargenScanner struct {
	config *ChargenFlags
}

func init() {
	var module ChargenModule
	_, err := zgrab2.AddCommand("chargen", "chargen", "Scan for chargen", 19, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (self *ChargenModule) NewFlags() interface{} {
	return new(ChargenFlags)
}

func (self *ChargenModule) NewScanner() zgrab2.Scanner {
	return new(ChargenScanner)
}

func (self *ChargenFlags) Validate(args []string) error {
	return nil
}

func (self *ChargenFlags) Help() string {
	return ""
}

func (self *ChargenScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*ChargenFlags)
	self.config = f
	return nil
}

func (self *ChargenScanner) InitPerSender(senderID int) error {
	return nil
}

func (self *ChargenScanner) GetName() string {
	return self.config.Name
}

func (self *ChargenScanner) GetPort() uint {
	return self.config.Port
}

func looksLikeChargen(buf []byte) bool {
	for _, v := range buf {
		if v >= 0x7f {
			return false
		}
	}
	str := string(buf)
	str = strings.Trim(str, "\r\n")
	lines := strings.Split(str, "\n")
	// Lines all the same length, except perhaps the last line
	for n := 1; n < len(lines)-1; n++ {
		line := lines[n]
		if len(line) != len(lines[n-1]) {
			return false
		}
		if len(line) < 20 {
			return false
		}
	}
	// Characters increment throughout the line, mod some value
	for _, line := range lines[1:] {
		jumps := 0
		line = strings.Trim(line, "\r\n")
		for i := 1; i < len(line); i++ {
			prev := line[i-1]
			ch := line[i]
			if ch != prev+1 {
				jumps++
				if ch >= prev {
					return false
				}
				if jumps > 1 {
					return false
				}
			}
		}
	}
	return true
}

func (self *ChargenScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	target := fmt.Sprintf("%s:%d", t.IP.String(), self.config.Port)
	var err error
	var local *net.UDPAddr = nil
	if self.config.LocalAddr != "" {
		local, err = net.ResolveUDPAddr("udp", self.config.LocalAddr)
		if err != nil {
			// panic?
			return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
		}
	}
	remote, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		// panic?
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
	}
	// TODO: timeout
	sock, err := net.DialUDP("udp", local, remote)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	result := &ChargenResults{}
	testPackets := [][]byte{
		[]byte{1},
		[]byte{0x31},
		[]byte{0x32, 0x33, 0x34, 0x0A, 0x0D},
		make([]byte, 512),
	}
	readBuf := make([]byte, 8192)
	for _, packet := range testPackets {
		n, err := sock.Write(packet)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		if n != len(packet) {
			return zgrab2.SCAN_UNKNOWN_ERROR, result, nil
		}
		if self.config.Timeout > 0 {
			sock.SetReadDeadline(time.Now().Add(time.Second * time.Duration(self.config.Timeout)))
		}

		n, err = sock.Read(readBuf)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		if result.OutputSize == nil || uint32(n) > *result.OutputSize {
			u32 := uint32(n)
			result.OutputSize = &u32
			temp := string(readBuf[0:n])
			result.OutputData = &temp
		}
		if !looksLikeChargen(readBuf[0:n]) {
			return zgrab2.SCAN_PROTOCOL_ERROR, result, fmt.Errorf("Data did not look like chargen")
		}
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}
