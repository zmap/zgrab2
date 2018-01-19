package modules

import "github.com/jb/tcpwrap"

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Section 6 of https://tools.ietf.org/html/rfc5905: times are relative to 1/1/1900 UTC
var NTPEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

var UnixEpoch = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

// Leap Indicator defined in figure 9 of https://tools.ietf.org/html/rfc5905
type LeapIndicator uint8

const (
	NoWarning     LeapIndicator = 0
	ExtraSecond                 = 1
	MissingSecond               = 2
	Unknown                     = 3
)

type AssociationMode uint8

const (
	Reserved         AssociationMode = 0
	SymmetricActive                  = 1
	SymmetricPassive                 = 2
	Client                           = 3
	Server                           = 4
	Broadcast                        = 5
	Control                          = 6
	Private                          = 7
)

// NTPFlags = LeapIndicator (2 bits) + Version (3 bits) + Mode (3 bits)
// Defined in https://tools.ietf.org/html/rfc5905 section 7.3
type NTPFlags uint8

func (self *NTPFlags) SetLeap(val LeapIndicator) {
	*self = NTPFlags((uint8(*self) & 0x3F) | uint8(val<<6))
}

func (self *NTPFlags) GetLeap() LeapIndicator {
	return LeapIndicator(*self >> 6)
}

func (self *NTPFlags) GetVersion() uint8 {
	return (uint8(*self) & 0x3F) >> 3
}

func (self *NTPFlags) SetVersion(val uint8) {
	*self = NTPFlags((uint8(*self) & 0xC7) | (val << 3))
}

func (self *NTPFlags) GetMode() AssociationMode {
	return AssociationMode(uint8(*self) & 0x07)
}

func (self *NTPFlags) SetMode(val AssociationMode) {
	*self = NTPFlags((uint8(*self) & 0xF8) | uint8(val))
}

// NTPShort a 32-bit fixed-length number defined in figure 3. The upper 16 bits are the seconds, the lower 16 bits are the fractional seconds.
type NTPShort uint32

func (self *NTPShort) GetSeconds() uint16 {
	return uint16(*self >> 16)
}

func (self *NTPShort) GetFraction() uint16 {
	return uint16(*self & 0x0000FFFF)
}

func (self *NTPShort) GetNanos() uint32 {
	// frac/2^16 = nanos/10^9
	// nanos = frac * 10^9 / 2^16
	return uint32(float32(self.GetFraction()) / float32(1<<16) * 1e9)
}

func (self *NTPShort) SetSeconds(val uint16) {
	*self = NTPShort((uint32(*self) & 0x0000FFFF) | uint32(val)<<16)
}

func (self *NTPShort) SetFraction(val uint16) {
	*self = NTPShort((uint32(*self) & 0xFFFF0000) | uint32(val))
}

func (self *NTPShort) GetDuration() time.Duration {
	return time.Duration(self.GetSeconds())*time.Second + time.Duration(self.GetNanos())*time.Nanosecond
}

func (self *NTPShort) SetDuration(d time.Duration) {
	ns := d.Nanoseconds()
	self.SetSeconds(uint16(ns / 1e9))
	frac := float32(ns%1e9) / float32(1e9) * 0x10000
	self.SetFraction(uint16(frac))
}

// NTPLong a 64-bit fixed-length number defined in figure 3. The upper 32 bits are the seconds, the lower 32 bits are the fractional seconds.
type NTPLong uint64

func (self *NTPLong) GetSeconds() uint32 {
	return uint32(*self >> 32)
}

func (self *NTPLong) GetFraction() uint32 {
	return uint32(*self & 0x000000FFFFFFFF)
}

func (self *NTPLong) SetSeconds(val uint32) {
	*self = NTPLong((uint64(*self) & uint64(0x000000FFFFFFFF)) | (uint64(val) << 32))
}

func (self *NTPLong) SetFraction(val uint32) {
	*self = NTPLong((uint64(*self) & uint64(0xFFFFFFFF00000000)) | uint64(val))
}

func (self *NTPLong) GetNanos() uint64 {
	return uint64(float64(self.GetFraction()) / float64(1<<32) * 1e9)
}

func (self *NTPLong) GetTime() time.Time {
	return NTPEpoch.Add(time.Duration(self.GetSeconds())*time.Second + time.Duration(self.GetNanos())*time.Nanosecond)
}

func (self *NTPLong) SetTime(t time.Time) {
	ntpTime := t.Add(UnixEpoch.Sub(NTPEpoch))
	s := ntpTime.Unix()
	ns := ntpTime.UnixNano() - s*1e9
	self.SetSeconds(uint32(s))
	self.SetFraction(uint32(float64(ns) / float64(10^9) * (1 << 32)))
}

type NTPHeader struct {
	// Flags contains the LeapIndicator, Version, and Mode.
	Flags NTPFlags `json:"flags"`

	// Stratum is defined in figure 11: values > 16 are reserved
	Stratum uint8 `json:"stratum"`

	// Poll: 8-bit signed integer representing the maximum interval between
	// successive messages, in log2 seconds.
	Poll int8 `json:"poll"`

	// Precision: 8-bit signed integer representing the precision of the system clock, in log2 seconds.
	Precision int8 `json:"precision"`

	// Root Delay: Total round-trip delay to the reference clock
	RootDelay NTPShort `json:"root_delay"`

	// Root Dispersion: Total dispersion to the reference clock
	RootDispersion NTPShort `json:"root_dispersion"`

	// Reference ID (refid): 32-bit code identifying the particular server or reference clock.
	ReferenceID [4]byte `json:"reference_id,omitempty"`

	// Reference Timestamp: Time when the system clock was last set or corrected
	ReferenceTimestamp NTPLong `json:"reference_timestamp,omitempty"`

	// Origin Timestamp (org): Time at the client when the request departed for the server
	OriginTimestamp NTPLong `json:"origin_timestamp,omitempty"`

	// Receive Timestamp (rec): Time at the server when the request arrived from the client
	ReceiveTimestamp NTPLong `json:"receive_timestamp,omitempty"`

	// Transmit Timestamp (xmt): Time at the server when the response left for the client
	TransmitTimestamp NTPLong `json:"transmit_timestamp,omitempty"`
}

var ErrInvalidVersion = fmt.Errorf("The version number was not valid")
var ErrInvalidMode = fmt.Errorf("The mode was 0")
var ErrInvalidStratum = fmt.Errorf("The stratum was invalid")
var ErrInvalidReferenceID = fmt.Errorf("The reference ID contained non-ASCII characters")

func (self *NTPHeader) ValidateSyntax() error {
	if self.Flags.GetVersion() < 3 || self.Flags.GetVersion() > 4 {
		return ErrInvalidVersion
	}
	if self.Flags.GetMode() == 0 {
		return ErrInvalidMode
	}
	if self.Stratum > 16 {
		return ErrInvalidStratum
	}
	if self.Stratum < 2 {
		// For packet stratum 0 [the reference ID] is a four-character ASCII string
		// called the "kiss code"... For stratum 1 (reference clock), this is a
		// four-octet, left-justified, zero-padded ASCII string
		for _, v := range self.ReferenceID {
			if v >= 0x7f {
				return ErrInvalidReferenceID
			}
		}
	}
	return nil
}

type NTPResults struct {
	Version *uint8     `json:"version,omitempty"`
	Time    *time.Time `json:"time,omitempty"`
}

type NTPConfig struct {
	zgrab2.BaseFlags
	Verbose   bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	LocalAddr string `long:"local-addr" description:"Set an explicit local address, in the format ip:port (e.g. 0.0.0.0:55555)"`
}

type NTPModule struct {
}

type NTPScanner struct {
	config *NTPConfig
}

func init() {
	var module NTPModule
	_, err := zgrab2.AddCommand("ntp", "NTP", "Scan for NTP", 123, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (self *NTPModule) NewFlags() interface{} {
	return new(NTPConfig)
}

func (self *NTPModule) NewScanner() zgrab2.Scanner {
	return new(NTPScanner)
}

func (self *NTPConfig) Validate(args []string) error {
	return nil
}

func (self *NTPConfig) Help() string {
	return ""
}

func (self *NTPScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*NTPConfig)
	self.config = f
	return nil
}

func (self *NTPScanner) InitPerSender(senderID int) error {
	return nil
}

func (self *NTPScanner) GetName() string {
	return self.config.Name
}

func (self *NTPScanner) GetPort() uint {
	return self.config.Port
}

func (self *NTPScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
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
	var sock net.Conn
	sock, err = net.DialUDP("udp", local, remote)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	sock = tcpwrap.Wrap(sock)
	outPacket := NTPHeader{}
	outPacket.Flags.SetMode(Client)
	outPacket.Flags.SetVersion(3)
	outPacket.Flags.SetLeap(Unknown)
	outPacket.Stratum = 0

	err = binary.Write(sock, binary.BigEndian, &outPacket)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	inPacket := NTPHeader{}
	err = binary.Read(sock, binary.BigEndian, &inPacket)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	err = inPacket.ValidateSyntax()
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}

	result := &NTPResults{}
	temp := inPacket.ReceiveTimestamp.GetTime()
	result.Time = &temp
	vTemp := inPacket.Flags.GetVersion()
	result.Version = &vTemp

	return zgrab2.SCAN_SUCCESS, result, nil
}
