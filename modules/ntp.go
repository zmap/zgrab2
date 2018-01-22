package modules

import (
	"encoding/binary"
	"fmt"
	"io"
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

// Constants from ntp/include/ntp_request.h
const (
	IMPL_UNIV      uint8 = 0
	IMPL_XNTPD_OLD       = 2
	IMPL_XNTPD           = 3
)

const (
	REQ_PEER_LIST     uint8 = 0
	REQ_MON_GETLIST_1       = 42
)

// NTPShort a 32-bit struct defined in figure 3. The upper 16 bits are the seconds, the lower 16 bits are the fractional seconds.
type NTPShort struct {
	Seconds  uint16 `json:"seconds"`
	Fraction uint16 `json:"fraction"`
}

func (self *NTPShort) Decode(buf []byte) error {
	if len(buf) < 4 {
		return ErrBufferTooSmall
	}
	self.Seconds = binary.BigEndian.Uint16(buf[0:2])
	self.Fraction = binary.BigEndian.Uint16(buf[2:4])
	return nil
}

func DecodeNTPShort(buf []byte) (*NTPShort, error) {
	if len(buf) < 4 {
		return nil, ErrBufferTooSmall
	}
	ret := NTPShort{}
	err := ret.Decode(buf)
	return &ret, err
}

func (self *NTPShort) Encode() []byte {
	ret := make([]byte, 4)
	binary.BigEndian.PutUint16(ret[0:2], self.Seconds)
	binary.BigEndian.PutUint16(ret[2:4], self.Fraction)
	return ret
}

func (self *NTPShort) GetNanos() uint32 {
	// frac/2^16 = nanos/10^9
	// nanos = frac * 10^9 / 2^16
	return uint32(float32(self.Fraction) / float32(1<<16) * 1e9)
}

func (self *NTPShort) SetNanos(nanos int) {
	frac := float32(nanos) / float32(1e9) * 0x10000
	self.Fraction = uint16(frac)
}

func (self *NTPShort) GetDuration() time.Duration {
	return time.Duration(self.Seconds)*time.Second + time.Duration(self.GetNanos())*time.Nanosecond
}

func (self *NTPShort) SetDuration(d time.Duration) {
	ns := d.Nanoseconds()
	self.Seconds = uint16(ns / 1e9)
	self.SetNanos(int(ns % 1e9))
}

// NTPLong a 64-bit fixed-length number defined in figure 3. The upper 32 bits are the seconds, the lower 32 bits are the fractional seconds.
type NTPLong struct {
	Seconds  uint32 `json:"seconds"`
	Fraction uint32 `json:"fraction"`
}

func (self *NTPLong) GetNanos() uint64 {
	return uint64(float64(self.Fraction) / float64(1<<32) * 1e9)
}

func (self *NTPLong) SetNanos(nanos int) {
	frac := float64(nanos) / float64(10^9) * (1 << 32)
	self.Fraction = uint32(frac)
}

func (self *NTPLong) GetTime() time.Time {
	return NTPEpoch.Add(time.Duration(self.Seconds)*time.Second + time.Duration(self.GetNanos())*time.Nanosecond)
}

func (self *NTPLong) SetTime(t time.Time) {
	ntpTime := t.Add(UnixEpoch.Sub(NTPEpoch))
	s := ntpTime.Unix()
	ns := ntpTime.UnixNano() - s*1e9
	self.Seconds = uint32(s)
	self.SetNanos(int(ns))
}

func (self *NTPLong) Decode(buf []byte) error {
	if len(buf) < 8 {
		return ErrBufferTooSmall
	}
	self.Seconds = binary.BigEndian.Uint32(buf[0:4])
	self.Fraction = binary.BigEndian.Uint32(buf[4:8])
	return nil
}

func DecodeNTPLong(buf []byte) (*NTPLong, error) {
	if len(buf) < 8 {
		return nil, ErrBufferTooSmall
	}
	ret := NTPLong{}
	err := ret.Decode(buf)
	return &ret, err
}

func (self *NTPLong) Encode() []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint32(ret[0:4], self.Seconds)
	binary.BigEndian.PutUint32(ret[4:8], self.Fraction)
	return ret
}

type NTPHeader struct {
	// LeapIndicator is the the top two bits of the first byte
	LeapIndicator LeapIndicator `json:"leap_indicator"`

	// Version is bits 5..3 of the first byte
	Version uint8 `json:"version"`

	// The mode is the lowest three bits of the first byte
	Mode AssociationMode `json:"mode"`

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

var ErrInvalidLeapIndicator = fmt.Errorf("The leap indicator was not valid")
var ErrInvalidVersion = fmt.Errorf("The version number was not valid")
var ErrInvalidMode = fmt.Errorf("The mode was 0")
var ErrInvalidStratum = fmt.Errorf("The stratum was invalid")
var ErrInvalidReferenceID = fmt.Errorf("The reference ID contained non-ASCII characters")
var ErrBufferTooSmall = fmt.Errorf("The buffer is too small")
var ErrInvalidHeader = fmt.Errorf("Invalid header data")

func DecodeNTPHeader(buf []byte) (*NTPHeader, error) {
	if len(buf) < 48 {
		return nil, ErrBufferTooSmall
	}
	ret := NTPHeader{}
	ret.LeapIndicator = LeapIndicator(buf[0] >> 6)
	ret.Version = uint8(buf[0] >> 3 & 0x07)
	ret.Mode = AssociationMode(buf[0] & 0x07)
	ret.Stratum = uint8(buf[1])
	ret.Poll = int8(buf[2])
	ret.Precision = int8(buf[3])
	if err := ret.RootDelay.Decode(buf[4:8]); err != nil {
		return nil, err
	}
	if err := ret.RootDispersion.Decode(buf[8:12]); err != nil {
		return nil, err
	}
	copy(ret.ReferenceID[:], buf[12:16])
	if err := ret.ReferenceTimestamp.Decode(buf[16:24]); err != nil {
		return nil, err
	}
	if err := ret.OriginTimestamp.Decode(buf[24:32]); err != nil {
		return nil, err
	}
	if err := ret.ReceiveTimestamp.Decode(buf[32:40]); err != nil {
		return nil, err
	}
	if err := ret.TransmitTimestamp.Decode(buf[40:48]); err != nil {
		return nil, err
	}

	return &ret, nil
}

func ReadNTPHeader(conn net.Conn) (*NTPHeader, error) {
	buf := make([]byte, 48)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return DecodeNTPHeader(buf)
}

func (self *NTPHeader) Encode() ([]byte, error) {
	ret := make([]byte, 48)
	if (self.Version >> 3) != 0 {
		return nil, ErrInvalidVersion
	}
	if (self.Mode >> 3) != 0 {
		return nil, ErrInvalidMode
	}
	if (self.LeapIndicator >> 2) != 0 {
		return nil, ErrInvalidLeapIndicator
	}
	ret[0] = byte((uint8(self.LeapIndicator) << 6) | (uint8(self.Mode) << 3) | uint8(self.Version))
	ret[1] = byte(self.Stratum)
	ret[2] = byte(self.Poll)
	ret[3] = byte(self.Precision)
	copy(ret[4:8], self.RootDelay.Encode())
	copy(ret[8:12], self.RootDispersion.Encode())
	copy(ret[12:16], self.ReferenceID[:])
	copy(ret[16:24], self.ReferenceTimestamp.Encode())
	copy(ret[24:32], self.OriginTimestamp.Encode())
	copy(ret[32:40], self.ReceiveTimestamp.Encode())
	copy(ret[40:48], self.TransmitTimestamp.Encode())

	return ret[:], nil
}

func (self *NTPHeader) ValidateSyntax() error {
	if self.Version < 2 || self.Version > 4 {
		return ErrInvalidVersion
	}
	if self.Mode == 0 {
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

type PrivatePacketHeader struct {
	IsResponse           bool   `json:"is_response"`
	HasMore              bool   `json:"has_more"`
	Version              uint8  `json:"version"`
	Mode                 uint8  `json:"version"`
	IsAuthenticated      bool   `json:"is_authenticated"`
	SequenceNumber       uint8  `json:"sequence_number"`
	ImplementationNumber uint8  `json:"implementation_number"`
	RequestCode          uint8  `json:"request_code"`
	Error                uint8  `json:"error"`
	NumRecords           uint16 `json:"num_records"`
	RecordSize           uint16 `json:"record_size"`
	MBZ                  uint8  `json:"mbz"`
}

func (self *PrivatePacketHeader) Encode() ([]byte, error) {
	ret := [8]byte{}
	if (self.Mode>>3) != 0 || (self.Version>>3) != 0 {
		return nil, ErrInvalidHeader
	}
	ret[0] = self.Mode | (self.Version << 3)
	if self.IsResponse {
		ret[0] = ret[0] | 0x80
	}
	if self.HasMore {
		ret[0] = ret[0] | 0x40
	}
	if self.SequenceNumber&0x80 != 0 {
		return nil, ErrInvalidHeader
	}
	ret[1] = self.SequenceNumber
	if self.IsAuthenticated {
		ret[1] = ret[1] | 0x80
	}
	ret[2] = self.ImplementationNumber
	ret[3] = self.RequestCode
	if (self.Error>>4) != 0 || (self.NumRecords>>12) != 0 {
		return nil, ErrInvalidHeader
	}
	ret[4] = (self.Error << 4) | uint8(self.NumRecords>>8)
	ret[5] = byte(self.NumRecords & 0xFF)
	if (self.MBZ>>4) != 0 || (self.RecordSize>>12) != 0 {
		return nil, ErrInvalidHeader
	}
	ret[6] = (self.MBZ << 4) | uint8(self.RecordSize>>8)
	ret[7] = byte(self.RecordSize & 0xFF)
	return ret[:], nil
}

func ReadPrivateModeHeader(buf []byte) (*PrivatePacketHeader, error) {
	ret := PrivatePacketHeader{}
	if len(buf) < 8 {
		return nil, ErrInvalidHeader
	}
	ret.Mode = buf[0] & 0x07
	ret.Version = buf[0] >> 3 & 0x07
	ret.IsResponse = (buf[0]>>6)&1 == 1
	ret.HasMore = (buf[0]>>7)&1 == 1
	ret.SequenceNumber = buf[1] & 0x7F
	ret.IsAuthenticated = (buf[1]>>7)&1 == 1
	ret.ImplementationNumber = buf[2]
	ret.RequestCode = buf[3]
	ret.Error = buf[4] >> 4
	ret.NumRecords = uint16(buf[4]&0x0F)<<4 | uint16(buf[5])
	ret.MBZ = buf[6] >> 4
	ret.RecordSize = uint16(buf[6]&0x0f)<<4 | uint16(buf[7])
	return &ret, nil
}

func NewMode7Packet(impl uint8, req uint8) *PrivatePacketHeader {
	return &PrivatePacketHeader{
		Version:              2,
		Mode:                 7,
		SequenceNumber:       0x00,
		ImplementationNumber: impl,
		RequestCode:          req,
		Error:                0x00,
	}
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
	outPacket := NTPHeader{}
	outPacket.Mode = Client
	outPacket.Version = 3
	outPacket.LeapIndicator = Unknown
	outPacket.Stratum = 0
	encoded, err := outPacket.Encode()
	if err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
	}
	_, err = sock.Write(encoded)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	inPacket, err := ReadNTPHeader(sock)
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
	vTemp := inPacket.Version
	result.Version = &vTemp

	return zgrab2.SCAN_SUCCESS, result, nil
}
