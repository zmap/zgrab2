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
	errInvalidLeapIndicator = errors.New("The leap indicator was not valid")
	errInvalidVersion       = errors.New("The version number was not valid")
	errInvalidMode          = errors.New("The mode was not valid")
	errInvalidStratum       = errors.New("The stratum was invalid")
	errInvalidReferenceID   = errors.New("The reference ID contained non-ASCII characters")
	errBufferTooSmall       = errors.New("The buffer is too small")
	errInvalidHeader        = errors.New("Invalid header data")
	errInvalidResponse      = errors.New("Invalid response")
	errInvalidRequestCode   = errors.New("The request code was invalid")
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
	implUniv     implNumber = 0
	implXNTPDOld            = 2
	implXNTPD               = 3
)

// These match the #define values in ntp_request.h
var implNumberMap = map[implNumber]string{
	implUniv:     "IMPL_UNIV",
	implXNTPDOld: "IMPL_XNTPD_OLD",
	implXNTPD:    "IMPL_XNTPD",
}

// MarshalJSON() gives the #define name, or "UNKNOWN (0x##)"
func (num implNumber) MarshalJSON() ([]byte, error) {
	ret, ok := implNumberMap[num]
	if !ok {
		ret = fmt.Sprintf("UNKNOWN (0x%02x)", num)
	}
	return json.Marshal(ret)
}

// Request codes are 8-bit values used in private packets, from ntp/include/ntp_request.h
type requestCode uint8

const (
	reqPeerList        requestCode = 0
	reqPeerListSum                 = 1
	reqPeerInfo                    = 2
	reqPeerStats                   = 3
	reqSysInfo                     = 4
	reqSysStats                    = 5
	reqIOStats                     = 6
	reqMemStats                    = 7
	reqLoopInfo                    = 8
	reqTimerStats                  = 9
	reqConfig                      = 10
	reqUnconfig                    = 11
	reqSetSysFlag                  = 12
	reqClrSysFlag                  = 13
	reqMonitor                     = 14
	reqNoMonitor                   = 15
	reqGetRestrict                 = 16
	reqResAddFlags                 = 17
	reqResSubFlags                 = 18
	rqeUnrestrict                  = 19
	reqMonGetList                  = 20
	reqResetStats                  = 21
	reqResetPeer                   = 22
	reqRereadKeys                  = 23
	reqDoDirtyHack                 = 24
	reqDontDirtyHack               = 25
	reqTrustKey                    = 26
	reqUntrustKey                  = 27
	reqAuthInfo                    = 28
	reqTraps                       = 29
	reqAddTrap                     = 30
	reqClrTrap                     = 31
	reqRequestKey                  = 32
	reqControlKey                  = 33
	reqGetCtlStats                 = 34
	reqGetLeapInfo                 = 35
	reqGetClockInfo                = 36
	reqSetClkFudge                 = 37
	reqGetKernel                   = 38
	reqGetClkBugInfo               = 39
	reqSetPrecision                = 41
	reqMonGetList1                 = 42
	reqHostnameAssocID             = 43
	reqIfStats                     = 44
	reqIfReload                    = 45
)

// These match the #defines in ntp-request.h
var requestCodeMap = map[string]requestCode{
	"REQ_PEER_LIST":        reqPeerList,
	"REQ_PEER_LIST_SUM":    reqPeerListSum,
	"REQ_PEER_INFO":        reqPeerInfo,
	"REQ_PEER_STATS":       reqPeerStats,
	"REQ_SYS_INFO":         reqSysInfo,
	"REQ_SYS_STATS":        reqSysStats,
	"REQ_IO_STATS":         reqIOStats,
	"REQ_MEM_STATS":        reqMemStats,
	"REQ_LOOP_INFO":        reqLoopInfo,
	"REQ_TIMER_STATS":      reqTimerStats,
	"REQ_CONFIG":           reqConfig,
	"REQ_UNCONFIG":         reqUnconfig,
	"REQ_SET_SYS_FLAG":     reqSetSysFlag,
	"REQ_CLR_SYS_FLAG":     reqClrSysFlag,
	"REQ_MONITOR":          reqMonitor,
	"REQ_NOMONITOR":        reqNoMonitor,
	"REQ_GET_RESTRICT":     reqGetRestrict,
	"REQ_RESADDFLAGS":      reqResAddFlags,
	"REQ_RESSUBFLAGS":      reqResSubFlags,
	"REQ_UNRESTRICT":       rqeUnrestrict,
	"REQ_MON_GETLIST":      reqMonGetList,
	"REQ_RESET_STATS":      reqResetStats,
	"REQ_RESET_PEER":       reqResetPeer,
	"REQ_REREAD_KEYS":      reqRereadKeys,
	"REQ_DO_DIRTY_HACK":    reqDoDirtyHack,
	"REQ_DONT_DIRTY_HACK":  reqDontDirtyHack,
	"REQ_TRUSTKEY":         reqTrustKey,
	"REQ_UNTRUSTKEY":       reqUntrustKey,
	"REQ_AUTHINFO":         reqAuthInfo,
	"REQ_TRAPS":            reqTraps,
	"REQ_ADD_TRAP":         reqAddTrap,
	"REQ_CLR_TRAP":         reqClrTrap,
	"REQ_REQUEST_KEY":      reqRequestKey,
	"REQ_CONTROL_KEY":      reqControlKey,
	"REQ_GET_CTLSTATS":     reqGetCtlStats,
	"REQ_GET_LEAPINFO":     reqGetLeapInfo,
	"REQ_GET_CLOCKINFO":    reqGetClockInfo,
	"REQ_SET_CLKFUDGE":     reqSetClkFudge,
	"REQ_GET_KERNEL":       reqGetKernel,
	"REQ_GET_CLKBUGINFO":   reqGetClkBugInfo,
	"REQ_SET_PRECISION":    reqSetPrecision,
	"REQ_MON_GETLIST_1":    reqMonGetList1,
	"REQ_HOSTNAME_ASSOCID": reqHostnameAssocID,
	"REQ_IF_STATS":         reqIfStats,
	"REQ_IF_RELOAD":        reqIfReload,
}

var reverseRequestCodeMap map[requestCode]string

// MarshalJSON() gives the #define name, or "UNKNOWN (0x##)"
func (code requestCode) MarshalJSON() ([]byte, error) {
	if reverseRequestCodeMap == nil {
		reverseRequestCodeMap = make(map[requestCode]string)
		for k, v := range requestCodeMap {
			reverseRequestCodeMap[v] = k
		}
	}
	ret, ok := reverseRequestCodeMap[code]
	if !ok {
		ret = fmt.Sprintf("UNKNOWN (0x%02x)", code)
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
	infoErrorUnknown5           = 5
	infoErrorUnknown6           = 6
	infoErrorAuth               = 7
)

// These match the #define names in ntp_rqeuest.h
var infoErrorMap = map[infoError]string{
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

// Error() implements the error interface (returns the #define name, or "UNKNOWN (0x##)")
func (err infoError) Error() string {
	ret, ok := infoErrorMap[err]
	if !ok {
		return fmt.Sprintf("UNKNOWN (0x%02x)", uint8(err))
	}
	return ret
}

// MarshalJSON() gives the #define name, or "UNKNOWN (0x##)"
func (err infoError) MarshalJSON() ([]byte, error) {
	return json.Marshal(err.Error())
}

// ntpShort a 32-bit struct defined in figure 3 of RFC5905.
type ntpShort struct {
	Seconds  uint16 `json:"seconds"`
	Fraction uint16 `json:"fraction"`
}

// Decode() populates the values of this ntpShort with the first 4 bytes of buf
func (when *ntpShort) Decode(buf []byte) error {
	if len(buf) < 4 {
		return errBufferTooSmall
	}
	when.Seconds = binary.BigEndian.Uint16(buf[0:2])
	when.Fraction = binary.BigEndian.Uint16(buf[2:4])
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

// Encode() encodes the ntpShort according to RFC5905 -- upper 16 bits the seconds, lower 16 bits the fractional seconds (big endian)
func (when *ntpShort) Encode() []byte {
	ret := make([]byte, 4)
	binary.BigEndian.PutUint16(ret[0:2], when.Seconds)
	binary.BigEndian.PutUint16(ret[2:4], when.Fraction)
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

// GetNanos() gets the number of nanoseconds represented by when.Fraction
func (when *ntpShort) GetNanos() uint32 {
	return uint32(uint16FracToNanos * float32(when.Fraction))
}

// SetNanos() sets when.Fraction to the binary fractional value corresponding to nanos nanoseconds
func (when *ntpShort) SetNanos(nanos int) {
	when.Fraction = uint16(nanosToUint16Frac * float32(nanos))
}

// GetDuration() gets the time.Duration corresponding to when
func (when *ntpShort) GetDuration() time.Duration {
	return time.Duration(when.Seconds)*time.Second + time.Duration(when.GetNanos())*time.Nanosecond
}

// SetDuration() sets the Seconds and Fraction to match the given duration
func (when *ntpShort) SetDuration(d time.Duration) {
	ns := d.Nanoseconds()
	when.Seconds = uint16(ns / 1e9)
	when.SetNanos(int(ns % 1e9))
}

// ntpLong is a 64-bit fixed-length number defined in figure 3 of RFC5905
type ntpLong struct {
	Seconds  uint32 `json:"seconds"`
	Fraction uint32 `json:"fraction"`
}

// GetNanos() gets the number of nanoseconds represented by when.Fraction
func (when *ntpLong) GetNanos() uint64 {
	return uint64(uint32FracToNanos * float64(when.Fraction))
}

// SetNanos() sets when.Fraction to the binary fractional value corresponding to nanos nanoseconds
func (when *ntpLong) SetNanos(nanos int) {
	when.Fraction = uint32(nanosToUint32Frac * float64(nanos))
}

// GetTime() gets the absolute time.Time corresponding to when
func (when *ntpLong) GetTime() time.Time {
	return ntpEpoch.Add(time.Duration(when.Seconds)*time.Second + time.Duration(when.GetNanos())*time.Nanosecond)
}

// SetTime() sets the absolute time.Time
func (when *ntpLong) SetTime(t time.Time) {
	ntpTime := t.Add(unixEpoch.Sub(ntpEpoch))
	// whole seconds
	s := ntpTime.Unix()
	// fractional nanoseconds
	ns := ntpTime.UnixNano() - s*1e9
	when.Seconds = uint32(s)
	when.SetNanos(int(ns))
}

// Decode() populates the values of this ntpShort with the first 8 bytes of buf
func (when *ntpLong) Decode(buf []byte) error {
	if len(buf) < 8 {
		return errBufferTooSmall
	}
	when.Seconds = binary.BigEndian.Uint32(buf[0:4])
	when.Fraction = binary.BigEndian.Uint32(buf[4:8])
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

// Encode() encodes the ntpShort according to RFC5905 -- upper 32 bits the seconds, lower 32 bits the fractional seconds (big endian)
func (when *ntpLong) Encode() []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint32(ret[0:4], when.Seconds)
	binary.BigEndian.PutUint32(ret[4:8], when.Fraction)
	return ret
}

// referenceID is defined in RFC5905 as a 32-bit code whose interpretation depends on the stratum field
type referenceID [4]byte

// MarshalJSON() ensures that it is marshalled like a slice, not an array
func (id referenceID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id[:])
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

// Encode() returns the encoding of the header according to RFC5905
func (header *ntpHeader) Encode() ([]byte, error) {
	ret := make([]byte, 48)
	if (header.Version >> 3) != 0 {
		return nil, errInvalidVersion
	}
	if (header.Mode >> 3) != 0 {
		return nil, errInvalidMode
	}
	if (header.LeapIndicator >> 2) != 0 {
		return nil, errInvalidLeapIndicator
	}
	ret[0] = byte((uint8(header.LeapIndicator) << 6) | (uint8(header.Mode) << 3) | uint8(header.Version))
	ret[1] = byte(header.Stratum)
	ret[2] = byte(header.Poll)
	ret[3] = byte(header.Precision)
	copy(ret[4:8], header.RootDelay.Encode())
	copy(ret[8:12], header.RootDispersion.Encode())
	copy(ret[12:16], header.ReferenceID[:])
	copy(ret[16:24], header.ReferenceTimestamp.Encode())
	copy(ret[24:32], header.OriginTimestamp.Encode())
	copy(ret[32:40], header.ReceiveTimestamp.Encode())
	copy(ret[40:48], header.TransmitTimestamp.Encode())

	return ret[:], nil
}

// ValidateSyntax() checks that the header's values are within range and make semantic sense
func (header *ntpHeader) ValidateSyntax() error {
	if header.Version < 1 || header.Version > 4 {
		return errInvalidVersion
	}
	if header.Mode == 0 {
		return errInvalidMode
	}
	if header.Stratum > 16 {
		return errInvalidStratum
	}
	if header.Stratum < 2 {
		// For packet stratum 0 [the reference ID] is a four-character ASCII string
		// called the "kiss code"... For stratum 1 (reference clock), this is a
		// four-octet, left-justified, zero-padded ASCII string
		for _, v := range header.ReferenceID {
			if v >= 0x7f {
				return errInvalidReferenceID
			}
		}
	}
	return nil
}

// privatePacketHeader represents a header for a mode-7 packet, roughly corresponding to struct resp_pkt in ntp_request.h
type privatePacketHeader struct {
	IsResponse           bool            `json:"is_response"`
	HasMore              bool            `json:"has_more"`
	Version              uint8           `json:"version"`
	Mode                 associationMode `json:"mode"`
	IsAuthenticated      bool            `json:"is_authenticated"`
	SequenceNumber       uint8           `json:"sequence_number"`
	ImplementationNumber implNumber      `json:"implementation_number"`
	RequestCode          requestCode     `json:"request_code"`
	Error                infoError       `json:"error"`
	NumItems             uint16          `json:"num_items"`
	MBZ                  uint8           `json:"mbz"`
	ItemSize             uint16          `json:"item_size"`
}

// Encode() encodes the packet header as a struct resp_pkt
func (header *privatePacketHeader) Encode() ([]byte, error) {
	ret := [8]byte{}
	if (header.Mode>>3) != 0 || (header.Version>>3) != 0 {
		return nil, errInvalidHeader
	}
	ret[0] = uint8(header.Mode) | (header.Version << 3)
	if header.IsResponse {
		ret[0] = ret[0] | 0x80
	}
	if header.HasMore {
		ret[0] = ret[0] | 0x40
	}
	if header.SequenceNumber&0x80 != 0 {
		return nil, errInvalidHeader
	}
	ret[1] = header.SequenceNumber
	if header.IsAuthenticated {
		ret[1] = ret[1] | 0x80
	}
	ret[2] = uint8(header.ImplementationNumber)
	ret[3] = uint8(header.RequestCode)
	if (header.Error>>4) != 0 || (header.NumItems>>12) != 0 {
		return nil, errInvalidHeader
	}
	ret[4] = (uint8(header.Error) << 4) | uint8(header.NumItems>>8)
	ret[5] = byte(header.NumItems & 0xFF)
	if (header.MBZ>>4) != 0 || (header.ItemSize>>12) != 0 {
		return nil, errInvalidHeader
	}
	ret[6] = (header.MBZ << 4) | uint8(header.ItemSize>>8)
	ret[7] = byte(header.ItemSize & 0xFF)
	return ret[:], nil
}

// Decode a private packet header from the first 8 bytes of buf
func decodePrivatePacketHeader(buf []byte) (*privatePacketHeader, error) {
	ret := privatePacketHeader{}
	if len(buf) < 8 {
		return nil, errInvalidHeader
	}
	ret.Mode = associationMode(buf[0] & 0x07)
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

// ntpConfig holds the command-line flags for the scanner.
type ntpConfig struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags
	Verbose       bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	Version       uint8  `long:"version" description:"The version number to pass to the server." default:"3"`
	LeapIndicator uint8  `long:"leap-indicator" description:"The LI value to pass to the server. Default 3 (unknown)"`
	SkipGetTime   bool   `long:"skip-get-time" description:"If set, don't request the server time"`
	MonList       bool   `long:"monlist" description:"Perform a reqMonGetList request"`
	RequestCode   string `long:"request-code" description:"Specify a request code for MonList other than reqMonGetList" default:"REQ_MON_GETLIST"`
}

// ntpModule is the zgrab2 module implementation
type ntpModule struct {
}

// ntpScanner holds the state for a single scan
type ntpScanner struct {
	config *ntpConfig
}

// init() registers the module with zgrab2
func init() {
	var module ntpModule
	_, err := zgrab2.AddCommand("ntp", "NTP", "Scan for NTP", 123, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (module *ntpModule) NewFlags() interface{} {
	return new(ntpConfig)
}

func (module *ntpModule) NewScanner() zgrab2.Scanner {
	return new(ntpScanner)
}

func (cfg *ntpConfig) Validate(args []string) error {
	return nil
}

func (cfg *ntpConfig) Help() string {
	return ""
}

func (scanner *ntpScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*ntpConfig)
	scanner.config = f
	return nil
}

func (scanner *ntpScanner) InitPerSender(senderID int) error {
	return nil
}

func (scanner *ntpScanner) GetName() string {
	return scanner.config.Name
}

func (scanner *ntpScanner) GetPort() uint {
	return scanner.config.Port
}

// SendAndReceive is a rough version of ntpdc.c's doquery(), except it only supports a single packet response
func (scanner *ntpScanner) SendAndReceive(impl implNumber, req requestCode, body []byte, sock net.Conn) (*privatePacketHeader, []byte, error) {
	outHeader, err := (&privatePacketHeader{
		Version:              scanner.config.Version,
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

// MonList() does a reqMonGetList call to the server and populates result with the output
func (scanner *ntpScanner) MonList(sock net.Conn, result *NTPResults) (zgrab2.ScanStatus, error) {
	reqCode, err := getRequestCode(scanner.config.RequestCode)
	if err != nil {
		panic(err)
	}
	body := make([]byte, 40)
	header, ret, err := scanner.SendAndReceive(implXNTPD, reqCode, body, sock)
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

// GetTime() sends a "client" packet to the server and reads / returns the response
func (scanner *ntpScanner) GetTime(sock net.Conn) (*ntpHeader, error) {
	outPacket := ntpHeader{}
	outPacket.Mode = client
	outPacket.Version = scanner.config.Version
	outPacket.LeapIndicator = leapIndicator(scanner.config.LeapIndicator)
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

func (scanner *ntpScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	sock, err := t.OpenUDP(&scanner.config.BaseFlags, &scanner.config.UDPFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	result := &NTPResults{}
	if !scanner.config.SkipGetTime {
		inPacket, err := scanner.GetTime(sock)
		if err != nil {
			// even if an inPacket is returned, it failed the syntax check, so indicate a failed detection via result == nil.
			return zgrab2.TryGetScanStatus(err), nil, err
		}
		temp := inPacket.ReceiveTimestamp.GetTime()
		result.TimeResponse = inPacket
		result.Time = &temp
		result.Version = &inPacket.Version
	}
	if scanner.config.MonList {
		status, err := scanner.MonList(sock, result)
		if err != nil {
			if scanner.config.SkipGetTime {
				// TODO: Currently, returning a non-nil result means that the service was positively detected.
				// It may be safer to add an explicit flag for this (status == success is not sufficient, since e.g. you can get a timeout after positively identifying the service)
				// This also means that partial TLS handshakes cannot be returned
				return status, nil, err
			}
			return status, result, err
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}
