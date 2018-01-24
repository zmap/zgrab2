package modules

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

var (
	errInvalidLeapIndicator error = errors.New("The leap indicator was not valid")
	errInvalidVersion             = errors.New("The version number was not valid")
	errInvalidMode                = errors.New("The mode was not valid")
	errInvalidStratum             = errors.New("The stratum was invalid")
	errInvalidReferenceID         = errors.New("The reference ID contained non-ASCII characters")
	errBufferTooSmall             = errors.New("The buffer is too small")
	errInvalidHeader              = errors.New("Invalid header data")
	errInvalidResponse            = errors.New("Invalid response")
	errInvalidRequestCode         = errors.New("The request code was invalid")
)

// Section 6 of https://tools.ietf.org/html/rfc5905: times are relative to 1/1/1900 UTC
var ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

var unixEpoch = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

// Leap Indicator is a two-bit field, whose values are defined in figure 9 of https://tools.ietf.org/html/rfc5905
type leapIndicator uint8

const (
	noWarning     leapIndicator = 0
	extraSecond                 = 1
	missingSecond               = 2
	unknown                     = 3
)

// Association mode is a three-bit value, whose values are defined in figure 9 of https://tools.ietf.org/html/rfc5905
type associationMode uint8

const (
	reserved         associationMode = 0
	symmetricActive                  = 1
	symmetricPassive                 = 2
	client                           = 3
	server                           = 4
	broadcast                        = 5
	control                          = 6
	private                          = 7
)

// implNumber is an 8-bit value used in private packets
type implNumber uint8

// Constants from ntp/include/ntp_request.h
const (
	IMPL_UNIV      implNumber = 0
	IMPL_XNTPD_OLD            = 2
	IMPL_XNTPD                = 3
)

// These match the #define values in ntp_request.h
var implNumberMap map[implNumber]string = map[implNumber]string{
	IMPL_UNIV:      "IMPL_UNIV",
	IMPL_XNTPD_OLD: "IMPL_XNTPD_OLD",
	IMPL_XNTPD:     "IMPL_XNTPD",
}

// implNumber.MarshalJSON() gives the #define name, or "UNKNOWN (0x##)"
func (self implNumber) MarshalJSON() ([]byte, error) {
	ret, ok := implNumberMap[self]
	if !ok {
		ret = fmt.Sprintf("UNKNOWN (0x%02x)", self)
	}
	return json.Marshal(ret)
}

// Request codes are 8-bit values used in private packets, from ntp/include/ntp_request.h
type requestCode uint8

const (
	REQ_PEER_LIST        requestCode = 0
	REQ_PEER_LIST_SUM                = 1
	REQ_PEER_INFO                    = 2
	REQ_PEER_STATS                   = 3
	REQ_SYS_INFO                     = 4
	REQ_SYS_STATS                    = 5
	REQ_IO_STATS                     = 6
	REQ_MEM_STATS                    = 7
	REQ_LOOP_INFO                    = 8
	REQ_TIMER_STATS                  = 9
	REQ_CONFIG                       = 10
	REQ_UNCONFIG                     = 11
	REQ_SET_SYS_FLAG                 = 12
	REQ_CLR_SYS_FLAG                 = 13
	REQ_MONITOR                      = 14
	REQ_NOMONITOR                    = 15
	REQ_GET_RESTRICT                 = 16
	REQ_RESADDFLAGS                  = 17
	REQ_RESSUBFLAGS                  = 18
	REQ_UNRESTRICT                   = 19
	REQ_MON_GETLIST                  = 20
	REQ_RESET_STATS                  = 21
	REQ_RESET_PEER                   = 22
	REQ_REREAD_KEYS                  = 23
	REQ_DO_DIRTY_HACK                = 24
	REQ_DONT_DIRTY_HACK              = 25
	REQ_TRUSTKEY                     = 26
	REQ_UNTRUSTKEY                   = 27
	REQ_AUTHINFO                     = 28
	REQ_TRAPS                        = 29
	REQ_ADD_TRAP                     = 30
	REQ_CLR_TRAP                     = 31
	REQ_REQUEST_KEY                  = 32
	REQ_CONTROL_KEY                  = 33
	REQ_GET_CTLSTATS                 = 34
	REQ_GET_LEAPINFO                 = 35
	REQ_GET_CLOCKINFO                = 36
	REQ_SET_CLKFUDGE                 = 37
	REQ_GET_KERNEL                   = 38
	REQ_GET_CLKBUGINFO               = 39
	REQ_SET_PRECISION                = 41
	REQ_MON_GETLIST_1                = 42
	REQ_HOSTNAME_ASSOCID             = 43
	REQ_IF_STATS                     = 44
	REQ_IF_RELOAD                    = 45
)

// These match the #defines in ntp-request.h
var requestCodeMap map[string]requestCode = map[string]requestCode{
	"REQ_PEER_LIST":        REQ_PEER_LIST,
	"REQ_PEER_LIST_SUM":    REQ_PEER_LIST_SUM,
	"REQ_PEER_INFO":        REQ_PEER_INFO,
	"REQ_PEER_STATS":       REQ_PEER_STATS,
	"REQ_SYS_INFO":         REQ_SYS_INFO,
	"REQ_SYS_STATS":        REQ_SYS_STATS,
	"REQ_IO_STATS":         REQ_IO_STATS,
	"REQ_MEM_STATS":        REQ_MEM_STATS,
	"REQ_LOOP_INFO":        REQ_LOOP_INFO,
	"REQ_TIMER_STATS":      REQ_TIMER_STATS,
	"REQ_CONFIG":           REQ_CONFIG,
	"REQ_UNCONFIG":         REQ_UNCONFIG,
	"REQ_SET_SYS_FLAG":     REQ_SET_SYS_FLAG,
	"REQ_CLR_SYS_FLAG":     REQ_CLR_SYS_FLAG,
	"REQ_MONITOR":          REQ_MONITOR,
	"REQ_NOMONITOR":        REQ_NOMONITOR,
	"REQ_GET_RESTRICT":     REQ_GET_RESTRICT,
	"REQ_RESADDFLAGS":      REQ_RESADDFLAGS,
	"REQ_RESSUBFLAGS":      REQ_RESSUBFLAGS,
	"REQ_UNRESTRICT":       REQ_UNRESTRICT,
	"REQ_MON_GETLIST":      REQ_MON_GETLIST,
	"REQ_RESET_STATS":      REQ_RESET_STATS,
	"REQ_RESET_PEER":       REQ_RESET_PEER,
	"REQ_REREAD_KEYS":      REQ_REREAD_KEYS,
	"REQ_DO_DIRTY_HACK":    REQ_DO_DIRTY_HACK,
	"REQ_DONT_DIRTY_HACK":  REQ_DONT_DIRTY_HACK,
	"REQ_TRUSTKEY":         REQ_TRUSTKEY,
	"REQ_UNTRUSTKEY":       REQ_UNTRUSTKEY,
	"REQ_AUTHINFO":         REQ_AUTHINFO,
	"REQ_TRAPS":            REQ_TRAPS,
	"REQ_ADD_TRAP":         REQ_ADD_TRAP,
	"REQ_CLR_TRAP":         REQ_CLR_TRAP,
	"REQ_REQUEST_KEY":      REQ_REQUEST_KEY,
	"REQ_CONTROL_KEY":      REQ_CONTROL_KEY,
	"REQ_GET_CTLSTATS":     REQ_GET_CTLSTATS,
	"REQ_GET_LEAPINFO":     REQ_GET_LEAPINFO,
	"REQ_GET_CLOCKINFO":    REQ_GET_CLOCKINFO,
	"REQ_SET_CLKFUDGE":     REQ_SET_CLKFUDGE,
	"REQ_GET_KERNEL":       REQ_GET_KERNEL,
	"REQ_GET_CLKBUGINFO":   REQ_GET_CLKBUGINFO,
	"REQ_SET_PRECISION":    REQ_SET_PRECISION,
	"REQ_MON_GETLIST_1":    REQ_MON_GETLIST_1,
	"REQ_HOSTNAME_ASSOCID": REQ_HOSTNAME_ASSOCID,
	"REQ_IF_STATS":         REQ_IF_STATS,
	"REQ_IF_RELOAD":        REQ_IF_RELOAD,
}

var reverseRequestCodeMap map[requestCode]string = nil

// requestCode.MarshalJSON() gives the #define name, or "UNKNOWN (0x##)"
func (self requestCode) MarshalJSON() ([]byte, error) {
	if reverseRequestCodeMap == nil {
		reverseRequestCodeMap = make(map[requestCode]string)
		for k, v := range requestCodeMap {
			reverseRequestCodeMap[v] = k
		}
	}
	ret, ok := reverseRequestCodeMap[self]
	if !ok {
		ret = fmt.Sprintf("UNKNOWN (0x%02x)", self)
	}
	return json.Marshal(ret)
}

// getRequestCode() returns the numeric value for the input string
// The input can either be a #define name from ntp_request.h or an integer
func getRequestCode(enum string) (requestCode, error) {
	ret, ok := requestCodeMap[enum]
	if ok {
		return ret, nil
	}
	v, err := strconv.ParseInt(enum, 0, 8)
	if err != nil {
		return 0, err
	}
	if v < 0 || v >= 0xff {
		return 0, errInvalidRequestCode
	}
	return requestCode(v), nil
}

// infoError is a 3-bit integer, values taken from ntp_request.h
type infoError uint8

const (
	infoErrorOkay     infoError = 0
	infoErrorImpl               = 1
	infoErrorReq                = 2
	infoErrorFmt                = 3
	infoErrorNoData             = 4
	InfoErrorUnknown5           = 5
	InfoErrorUnknown6           = 6
	infoErrorAuth               = 7
)

// These match the #define names in ntp_rqeuest.h
var infoErrorMap map[infoError]string = map[infoError]string{
	infoErrorOkay:   "INFO_OKAY",
	infoErrorImpl:   "INFO_ERR_IMPL",
	infoErrorReq:    "INFO_ERR_REQ",
	infoErrorFmt:    "INFO_ERR_FMT",
	infoErrorNoData: "INFO_ERR_NODATA",
	infoErrorAuth:   "INFO_ERR_AUTH",
}

// isInfoError() checks if err is an instance of infoError
func isInfoError(err error) bool {
	_, ok := err.(infoError)
	return ok
}

// infoError.Error() implements the error interface (returns the #define name, or "UNKNOWN (0x##)")
func (self infoError) Error() string {
	ret, ok := infoErrorMap[self]
	if !ok {
		return fmt.Sprintf("UNKNOWN (0x%02x)", uint8(self))
	}
	return ret
}

// infoError.MarshalJSON() gives the #define name, or "UNKNOWN (0x##)"
func (self infoError) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.Error())
}

// ntpShort a 32-bit struct defined in figure 3 of RFC5905.
type ntpShort struct {
	Seconds  uint16 `json:"seconds"`
	Fraction uint16 `json:"fraction"`
}

// ntpShort.Decode() populates the values of this ntpShort with the first 4 bytes of buf
func (self *ntpShort) Decode(buf []byte) error {
	if len(buf) < 4 {
		return errBufferTooSmall
	}
	self.Seconds = binary.BigEndian.Uint16(buf[0:2])
	self.Fraction = binary.BigEndian.Uint16(buf[2:4])
	return nil
}

// decodeNTPShort() decodes an ntpShort from the first 4 bytes of buf
func decodeNTPShort(buf []byte) (*ntpShort, error) {
	if len(buf) < 4 {
		return nil, errBufferTooSmall
	}
	ret := ntpShort{}
	err := ret.Decode(buf)
	return &ret, err
}

// ntpShort.Encode() encodes the ntpShort according to RFC5905 -- upper 16 bits the seconds, lower 16 bits the fractional seconds (big endian)
func (self *ntpShort) Encode() []byte {
	ret := make([]byte, 4)
	binary.BigEndian.PutUint16(ret[0:2], self.Seconds)
	binary.BigEndian.PutUint16(ret[2:4], self.Fraction)
	return ret
}

// Conversion constants for going from binary fractional seconds to nanoseconds
// fraction/(1 << bits) = nanos/1e9
// nanos = fraction * 1e9 / (1 << bits)
// fraction = nanos * (1 << bits) / 1e9
const (
	uint16FracToNanos float32 = float32(1e9) / float32(1<<16)
	uint32FracToNanos float64 = float64(1e9) / float64(1<<32)
	nanosToUint16Frac float32 = float32(1<<16) / float32(1e9)
	nanosToUint32Frac float64 = float64(1<<32) / float64(1e9)
)

// ntpShort.GetNanos() gets the number of nanoseconds represented by self.Fraction
func (self *ntpShort) GetNanos() uint32 {
	return uint32(uint16FracToNanos * float32(self.Fraction))
}

// ntpShort.SetNanos() sets self.Fraction to the binary fractional value corresponding to nanos nanoseconds
func (self *ntpShort) SetNanos(nanos int) {
	self.Fraction = uint16(nanosToUint16Frac * float32(nanos))
}

// ntpShort.GetDuration() gets the time.Duration corresponding to self
func (self *ntpShort) GetDuration() time.Duration {
	return time.Duration(self.Seconds)*time.Second + time.Duration(self.GetNanos())*time.Nanosecond
}

// ntpShort.SetDuration() sets the Seconds and Fraction to match the given duration
func (self *ntpShort) SetDuration(d time.Duration) {
	ns := d.Nanoseconds()
	self.Seconds = uint16(ns / 1e9)
	self.SetNanos(int(ns % 1e9))
}

// ntpLong a 64-bit fixed-length number defined in figure 3 of RFC5905
type ntpLong struct {
	Seconds  uint32 `json:"seconds"`
	Fraction uint32 `json:"fraction"`
}

// ntpLong.GetNanos() gets the number of nanoseconds represented by self.Fraction
func (self *ntpLong) GetNanos() uint64 {
	return uint64(uint32FracToNanos * float64(self.Fraction))
}

// ntpLong.SetNanos() sets self.Fraction to the binary fractional value corresponding to nanos nanoseconds
func (self *ntpLong) SetNanos(nanos int) {
	self.Fraction = uint32(nanosToUint32Frac * float64(nanos))
}

// ntpLong.GetTime() gets the absolute time.Time corresponding to self
func (self *ntpLong) GetTime() time.Time {
	return ntpEpoch.Add(time.Duration(self.Seconds)*time.Second + time.Duration(self.GetNanos())*time.Nanosecond)
}

// ntpLong.SetTime() sets the absolute time.Time
func (self *ntpLong) SetTime(t time.Time) {
	ntpTime := t.Add(unixEpoch.Sub(ntpEpoch))
	// whole seconds
	s := ntpTime.Unix()
	// fractional nanoseconds
	ns := ntpTime.UnixNano() - s*1e9
	self.Seconds = uint32(s)
	self.SetNanos(int(ns))
}

// ntpLong.Decode() populates the values of this ntpShort with the first 8 bytes of buf
func (self *ntpLong) Decode(buf []byte) error {
	if len(buf) < 8 {
		return errBufferTooSmall
	}
	self.Seconds = binary.BigEndian.Uint32(buf[0:4])
	self.Fraction = binary.BigEndian.Uint32(buf[4:8])
	return nil
}

// decodeNTPLong() decodes an ntpShort from the first 8 bytes of buf
func decodeNTPLong(buf []byte) (*ntpLong, error) {
	if len(buf) < 8 {
		return nil, errBufferTooSmall
	}
	ret := ntpLong{}
	err := ret.Decode(buf)
	return &ret, err
}

// ntpLong.Encode() encodes the ntpShort according to RFC5905 -- upper 32 bits the seconds, lower 32 bits the fractional seconds (big endian)
func (self *ntpLong) Encode() []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint32(ret[0:4], self.Seconds)
	binary.BigEndian.PutUint32(ret[4:8], self.Fraction)
	return ret
}

// referenceID is defined in RFC5905 as a 32-bit code whose interpretation depends on the stratum field
type referenceID [4]byte

// referenceID.MarshalJSON() ensures that it is marshalled like a slice, not an array
func (self referenceID) MarshalJSON() ([]byte, error) {
	return json.Marshal(self[:])
}

// ntpHeader is defined in figure 8 of RFC5905
type ntpHeader struct {
	// leapIndicator is the the top two bits of the first byte
	LeapIndicator leapIndicator `json:"leap_indicator"`

	// Version is bits 5..3 of the first byte
	Version uint8 `json:"version"`

	// The mode is the lowest three bits of the first byte
	Mode associationMode `json:"mode"`

	// Stratum is defined in figure 11: values > 16 are reserved
	Stratum uint8 `json:"stratum"`

	// Poll: 8-bit signed integer representing the maximum interval between
	// successive messages, in log2 seconds.
	Poll int8 `json:"poll"`

	// Precision: 8-bit signed integer representing the precision of the system clock, in log2 seconds.
	Precision int8 `json:"precision"`

	// Root Delay: Total round-trip delay to the reference clock
	RootDelay ntpShort `json:"root_delay"`

	// Root Dispersion: Total dispersion to the reference clock
	RootDispersion ntpShort `json:"root_dispersion"`

	// Reference ID (refid): 32-bit code identifying the particular server or reference clock.
	ReferenceID referenceID `json:"reference_id,omitempty"`

	// Reference Timestamp: Time when the system clock was last set or corrected
	ReferenceTimestamp ntpLong `json:"reference_timestamp,omitempty"`

	// Origin Timestamp (org): Time at the client when the request departed for the server
	OriginTimestamp ntpLong `json:"origin_timestamp,omitempty"`

	// Receive Timestamp (rec): Time at the server when the request arrived from the client
	ReceiveTimestamp ntpLong `json:"receive_timestamp,omitempty"`

	// Transmit Timestamp (xmt): Time at the server when the response left for the client
	TransmitTimestamp ntpLong `json:"transmit_timestamp,omitempty"`
}

// decodeNTPHeader decodes an NTP header from the first 48 bytes of buf
func decodeNTPHeader(buf []byte) (*ntpHeader, error) {
	if len(buf) < 48 {
		return nil, errBufferTooSmall
	}
	ret := ntpHeader{}
	ret.LeapIndicator = leapIndicator(buf[0] >> 6)
	ret.Version = uint8(buf[0] >> 3 & 0x07)
	ret.Mode = associationMode(buf[0] & 0x07)
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

// readNTPHeader() reads 48 bytes from conn and interprets it as an NTPHeader
func readNTPHeader(conn net.Conn) (*ntpHeader, error) {
	buf := make([]byte, 48)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return decodeNTPHeader(buf)
}

// ntpHeader.Encode() returns the encoding of the header according to RFC5905
func (self *ntpHeader) Encode() ([]byte, error) {
	ret := make([]byte, 48)
	if (self.Version >> 3) != 0 {
		return nil, errInvalidVersion
	}
	if (self.Mode >> 3) != 0 {
		return nil, errInvalidMode
	}
	if (self.LeapIndicator >> 2) != 0 {
		return nil, errInvalidLeapIndicator
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

// ntpHeader.ValidateSyntax() checks that the header's values are within range and make semantic sense
func (self *ntpHeader) ValidateSyntax() error {
	if self.Version < 1 || self.Version > 4 {
		return errInvalidVersion
	}
	if self.Mode == 0 {
		return errInvalidMode
	}
	if self.Stratum > 16 {
		return errInvalidStratum
	}
	if self.Stratum < 2 {
		// For packet stratum 0 [the reference ID] is a four-character ASCII string
		// called the "kiss code"... For stratum 1 (reference clock), this is a
		// four-octet, left-justified, zero-padded ASCII string
		for _, v := range self.ReferenceID {
			if v >= 0x7f {
				return errInvalidReferenceID
			}
		}
	}
	return nil
}

// privatePacketHeader represents a header for a mode-7 packet, roughly corresponding to struct resp_pkt in ntp_request.h
type privatePacketHeader struct {
	IsResponse           bool        `json:"is_response"`
	HasMore              bool        `json:"has_more"`
	Version              uint8       `json:"version"`
	Mode                 uint8       `json:"mode"`
	IsAuthenticated      bool        `json:"is_authenticated"`
	SequenceNumber       uint8       `json:"sequence_number"`
	ImplementationNumber implNumber  `json:"implementation_number"`
	RequestCode          requestCode `json:"request_code"`
	Error                infoError   `json:"error"`
	NumItems             uint16      `json:"num_records"`
	MBZ                  uint8       `json:"mbz"`
	ItemSize             uint16      `json:"record_size"`
}

// privatePacketHeader.Encode() encodes the packet header as a struct resp_pkt
func (self *privatePacketHeader) Encode() ([]byte, error) {
	ret := [8]byte{}
	if (self.Mode>>3) != 0 || (self.Version>>3) != 0 {
		return nil, errInvalidHeader
	}
	ret[0] = self.Mode | (self.Version << 3)
	if self.IsResponse {
		ret[0] = ret[0] | 0x80
	}
	if self.HasMore {
		ret[0] = ret[0] | 0x40
	}
	if self.SequenceNumber&0x80 != 0 {
		return nil, errInvalidHeader
	}
	ret[1] = self.SequenceNumber
	if self.IsAuthenticated {
		ret[1] = ret[1] | 0x80
	}
	ret[2] = uint8(self.ImplementationNumber)
	ret[3] = uint8(self.RequestCode)
	if (self.Error>>4) != 0 || (self.NumItems>>12) != 0 {
		return nil, errInvalidHeader
	}
	ret[4] = (uint8(self.Error) << 4) | uint8(self.NumItems>>8)
	ret[5] = byte(self.NumItems & 0xFF)
	if (self.MBZ>>4) != 0 || (self.ItemSize>>12) != 0 {
		return nil, errInvalidHeader
	}
	ret[6] = (self.MBZ << 4) | uint8(self.ItemSize>>8)
	ret[7] = byte(self.ItemSize & 0xFF)
	return ret[:], nil
}

// Decode a private packet header from the first 8 bytes of buf
func decodePrivatePacketHeader(buf []byte) (*privatePacketHeader, error) {
	ret := privatePacketHeader{}
	if len(buf) < 8 {
		return nil, errInvalidHeader
	}
	ret.Mode = buf[0] & 0x07
	ret.Version = buf[0] >> 3 & 0x07
	ret.HasMore = (buf[0]>>6)&1 == 1
	ret.IsResponse = (buf[0]>>7)&1 == 1
	ret.SequenceNumber = buf[1] & 0x7F
	ret.IsAuthenticated = (buf[1]>>7)&1 == 1
	ret.ImplementationNumber = implNumber(buf[2])
	ret.RequestCode = requestCode(buf[3])
	ret.Error = infoError(buf[4] >> 4)
	ret.NumItems = uint16(buf[4]&0x0F)<<4 | uint16(buf[5])
	ret.MBZ = buf[6] >> 4
	ret.ItemSize = uint16(buf[6]&0x0f)<<4 | uint16(buf[7])
	return &ret, nil
}

// NTPResults is the struct that is returned to the zgrab2 framework from Scan()
type NTPResults struct {
	// Version is the version number returned in the time response header. Absent if --skip-get-time is set.
	Version *uint8 `json:"version,omitempty"`

	// Time is the time returned by the server (specifically, the ReceiveTimestamp). Converted into standard golang time. Absent if --skip-get-time is set.
	Time *time.Time `json:"time,omitempty"`

	// TimeResponse is the full header returned by the get time call. Absent if --skip-get-time is set.
	TimeResponse *ntpHeader `json:"time_response,omitempty" zgrab:"debug"`

	// MonListResponse is the data returned by the call to monlist. Only present if --monlist is set.
	MonListResponse []byte `json:"monlist_response,omitempty"`

	// MonListHeader is the header returned by the call to monlist. Only present if --monlist is set.
	MonListHeader *privatePacketHeader `json:"monlist_header,omitempty" zgrab:"debug"`
}

// NTPConfig holds the command-line flags for the scanner.
type NTPConfig struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags
	Verbose       bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	Version       uint8  `long:"version" description:"The version number to pass to the server." default:"3"`
	LeapIndicator uint8  `long:"leap-indicator" description:"The LI value to pass to the server. Default 3 (unknown)"`
	SkipGetTime   bool   `long:"skip-get-time" description:"If set, don't request the server time"`
	MonList       bool   `long:"monlist" description:"Perform a REQ_MON_GETLIST request"`
	RequestCode   string `long:"request-code" description:"Specify a request code for MonList other than REQ_MON_GETLIST" default:"REQ_MON_GETLIST"`
}

// NTPModule is the zgrab2 module implementation
type NTPModule struct {
}

// NTPScanner holds the state for a single scan
type NTPScanner struct {
	config *NTPConfig
}

// init() registers the module with zgrab2
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

// NTPScanner.SendAndReceive is a rough version of ntpdc.c's doquery(), except it only supports a single packet response
func (self *NTPScanner) SendAndReceive(impl implNumber, req requestCode, body []byte, sock net.Conn) (*privatePacketHeader, []byte, error) {
	outHeader, err := (&privatePacketHeader{
		Version:              self.config.Version,
		Mode:                 7,
		SequenceNumber:       0x00,
		ImplementationNumber: impl,
		RequestCode:          req,
		Error:                0x00,
	}).Encode()
	if err != nil {
		return nil, nil, err
	}
	outPacket := append(outHeader, body...)
	n, err := sock.Write(outPacket)
	if err != nil {
		return nil, nil, err
	}
	if n != len(outPacket) {
		return nil, nil, err
	}
	buf := make([]byte, 512)
	n, err = sock.Read(buf)
	if err != nil || n == 0 {
		return nil, nil, err
	}
	if n < 8 {
		log.Debugf("Returned data too small (%d bytes)", n)
		return nil, nil, err
	}
	response := buf[0:n]
	inPacket, err := decodePrivatePacketHeader(response)
	if err != nil {
		return inPacket, nil, err
	}
	// Validation logic taken from getresponse@ntpdc/ntpdc.c
	// check if version is in bounds
	if inPacket.Mode != private {
		log.Debugf("Received non private-mode packet (mode=0x%02x), packet=%v", inPacket.Mode, inPacket)
		return inPacket, nil, err
	}
	if !inPacket.IsResponse {
		log.Debugf("Received non response packet (mode=0x%02x), packet=%v", inPacket.Mode, inPacket)
		return inPacket, nil, err
	}
	if inPacket.MBZ != 0 {
		log.Debugf("Received nonzero MBZ in response packet (mbz=0x%02x), packet=%v", inPacket.MBZ, inPacket)
		// TODO: continue?
		return inPacket, nil, err
	}
	if inPacket.ImplementationNumber != impl {
		log.Debugf("Received mismatched implementation number in response packe (expected 0x%02x, got 0x%02x), packet=%v", impl, inPacket.ImplementationNumber, inPacket)
		// TODO: continue?
		return inPacket, nil, err
	}
	if inPacket.Error != infoErrorOkay {
		log.Debugf("Got error in non-final response packet (error=0x%02x), packet=%v", inPacket.Error, inPacket)
		return inPacket, nil, inPacket.Error
	}
	ret := response[8:]
	if len(ret) != int(inPacket.ItemSize*inPacket.NumItems) {
		log.Debugf("Body length (%d) does not match record size (%d) * num records (%d)", len(ret), inPacket.ItemSize, inPacket.NumItems)
		return inPacket, ret, errInvalidResponse
	}
	return inPacket, ret, nil
}

// NTPScanner.MonList() does a REQ_MON_GETLIST call to the server and populates result with the output
func (self *NTPScanner) MonList(sock net.Conn, result *NTPResults) (zgrab2.ScanStatus, error) {
	reqCode, err := getRequestCode(self.config.RequestCode)
	if err != nil {
		panic(err)
	}
	body := make([]byte, 40)
	header, ret, err := self.SendAndReceive(IMPL_XNTPD, reqCode, body, sock)
	if ret != nil {
		result.MonListResponse = ret
	}
	if header != nil {
		result.MonListHeader = header
	}
	if err != nil {
		switch {
		case err == errInvalidResponse:
			// Response packet had invalid syntax or semantics
			return zgrab2.SCAN_PROTOCOL_ERROR, err
		case isInfoError(err):
			return zgrab2.SCAN_APPLICATION_ERROR, err
		default:
			return zgrab2.TryGetScanStatus(err), err
		}
	}
	return zgrab2.SCAN_SUCCESS, err
}

func (self *NTPScanner) GetTime(sock net.Conn) (*ntpHeader, error) {
	outPacket := ntpHeader{}
	outPacket.Mode = client
	outPacket.Version = self.config.Version
	// TODO: Configurable
	outPacket.LeapIndicator = unknown
	outPacket.Stratum = 0
	encoded, err := outPacket.Encode()
	if err != nil {
		return nil, err
	}
	_, err = sock.Write(encoded)
	if err != nil {
		return nil, err
	}

	inPacket, err := readNTPHeader(sock)
	if err != nil {
		return nil, err
	}
	err = inPacket.ValidateSyntax()
	if err != nil {
		return inPacket, err
	}
	return inPacket, nil
}

func (self *NTPScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	sock, err := t.OpenUDP(&self.config.BaseFlags, &self.config.UDPFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	result := &NTPResults{}
	if !self.config.SkipGetTime {
		inPacket, err := self.GetTime(sock)
		if inPacket != nil {
			temp := inPacket.ReceiveTimestamp.GetTime()
			result.TimeResponse = inPacket
			result.Time = &temp
			result.Version = &inPacket.Version
		}
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}
	}
	if self.config.MonList {
		status, err := self.MonList(sock, result)
		if err != nil {
			if self.config.SkipGetTime {
				// TODO: Currently, returning a non-nil result means that the service was positively detected.
				// It may be safer to add an explicit flag for this (status == success is not sufficient, since e.g. you can get a timeout after positively identifying the service)
				return status, nil, err
			} else {
				return status, result, err
			}
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}
