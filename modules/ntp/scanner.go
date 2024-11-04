// Package ntp provides a zgrab2 module that probes for the NTP service.
// NOTE: unlike most modules, this scans on UDP.
//
// The default scan does a standard get time request.
//
// Passing the monlist flag will check for the DDoS-amplifying MONLIST command.
//
// The results of the scan are the version number and the time returned by the
// server, and if verbose results are enabled, the entire parsed response
// packet(s).
//
// For more details on NTP, see https://tools.ietf.org/html/rfc5905.
package ntp

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
	// ErrInvalidLeapIndicator is returned if an invalid LeapIndicator is found
	ErrInvalidLeapIndicator = errors.New("leap indicator not valid")

	// ErrInvalidVersion is returned if an invalid version number is found
	ErrInvalidVersion = errors.New("version number not valid")

	// ErrInvalidMode is returned if an invalid mode identifier is found
	ErrInvalidMode = errors.New("mode not valid")

	// ErrInvalidStratum is returned if an invalid stratum identifier is found
	ErrInvalidStratum = errors.New("stratum invalid")

	// ErrInvalidReferenceID is returned if an invalid reference ID is found (i.e. it contains non-ASCII characters)
	ErrInvalidReferenceID = errors.New("reference ID contained non-ASCII characters")

	// ErrBufferTooSmall is returned if a buffer is not large enough to contain the input
	ErrBufferTooSmall = errors.New("buffer too small")

	// ErrInvalidHeader is returned if the header cannot be interpreted as a valid NTP header
	ErrInvalidHeader = errors.New("invalid header data")

	// ErrInvalidResponse is returned if the response cannot be interpreted as a valid NTP response
	ErrInvalidResponse = errors.New("invalid response")

	// ErrInvalidRequestCode is returned if an invalid RequestCode is found
	ErrInvalidRequestCode = errors.New("request code invalid")
)

// Section 6 of https://tools.ietf.org/html/rfc5905: times are relative to 1/1/1900 UTC
var ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

var unixEpoch = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

// LeapIndicator is a two-bit field, whose values are defined in figure 9 of https://tools.ietf.org/html/rfc5905
type LeapIndicator uint8

const (
	// NoWarning is a LeapIndicator that indicates that there is no problem
	NoWarning LeapIndicator = 0

	// ExtraSecond is a LeapIndicator that indicates that the last minute has 61 seconds
	ExtraSecond = 1

	// MissingSecond is a LeapIndicator that indicates that the last minute has 59 seconds
	MissingSecond = 2

	// Unknown is a LeapIndicator that indicates an unknown alarm condition
	Unknown = 3
)

// AssociationMode is a three-bit value, whose values are defined in figure 9 of https://tools.ietf.org/html/rfc5905
type AssociationMode uint8

const (
	// Reserved is a reserved AssociationMode
	Reserved AssociationMode = 0

	// SymmetricActive is an AssociationMode indicating that the service is in the active symmetric mode
	SymmetricActive = 1

	// SymmetricPassive is an AssociationMode indicating that the service is in the passive symmetric mode
	SymmetricPassive = 2

	// Client is an AssociationMode indicating that the caller is a client
	Client = 3

	// Server is an AssociationMode indicating that the packet is to be interpreted as a server
	Server = 4

	// Broadcast is an AssociationMode indicating that the this is a broadcast packet
	Broadcast = 5

	// Control is an AssociationMode reserved for NTP control messages
	Control = 6

	// Private is an AssociationMode reserved for private use
	Private = 7
)

// ImplNumber is an 8-bit value used in Private packets
type ImplNumber uint8

// Constants from ntp/include/ntp_request.h
const (
	// ImplUniv corresponds to the IMPL_UNIV constant
	ImplUniv ImplNumber = 0

	// ImplXNTPDOld corresponds to the IMPL_XNTPD_OLD constant
	ImplXNTPDOld = 2

	// ImplXNTPD corresponds to the IMPL_XNTPD constant
	ImplXNTPD = 3
)

// These match the #define values in ntp_request.h
var implNumberMap = map[ImplNumber]string{
	ImplUniv:     "IMPL_UNIV",
	ImplXNTPDOld: "IMPL_XNTPD_OLD",
	ImplXNTPD:    "IMPL_XNTPD",
}

// MarshalJSON gives the #define name, or "UNKNOWN (0x##)"
func (num ImplNumber) MarshalJSON() ([]byte, error) {
	ret, ok := implNumberMap[num]
	if !ok {
		ret = fmt.Sprintf("UNKNOWN (0x%02x)", num)
	}
	return json.Marshal(ret)
}

// RequestCode is an 8-bit value used in Private packets, from ntp/include/ntp_request.h
type RequestCode uint8

const (
	// ReqPeerList corresponds to the REQ_PEER_LIST constant
	ReqPeerList RequestCode = 0

	// ReqPeerListSum  corresponds to the REQ_PEER_LIST_SUM constant
	ReqPeerListSum = 1

	// ReqPeerInfo  corresponds to the REQ_PEER_INFO constant
	ReqPeerInfo = 2

	// ReqPeerStats  corresponds to the REQ_PEER_STATS constant
	ReqPeerStats = 3

	// ReqSysInfo  corresponds to the REQ_SYS_INFO constant
	ReqSysInfo = 4

	// ReqSysStats  corresponds to the REQ_SYS_STATS constant
	ReqSysStats = 5

	// ReqIOStats  corresponds to the REQ_IO_STATS constant
	ReqIOStats = 6

	// ReqMemStats  corresponds to the REQ_MEM_STATS constant
	ReqMemStats = 7

	// ReqLoopInfo  corresponds to the REQ_LOOP_INFO constant
	ReqLoopInfo = 8

	// ReqTimerStats  corresponds to the REQ_TIMER_STATS constant
	ReqTimerStats = 9

	// ReqConfig  corresponds to the REQ_CONFIG constant
	ReqConfig = 10

	// ReqUnconfig  corresponds to the REQ_UNCONFIG constant
	ReqUnconfig = 11

	// ReqSetSysFlag  corresponds to the REQ_SET_SYS_FLAG constant
	ReqSetSysFlag = 12

	// ReqClrSysFlag  corresponds to the REQ_CLR_SYS_FLAG constant
	ReqClrSysFlag = 13

	// ReqMonitor  corresponds to the REQ_MONITOR constant
	ReqMonitor = 14

	// ReqNoMonitor  corresponds to the REQ_NOMONITOR constant
	ReqNoMonitor = 15

	// ReqGetRestrict  corresponds to the REQ_GET_RESTRICT constant
	ReqGetRestrict = 16

	// ReqResAddFlags  corresponds to the REQ_RES_ADD_FLAGS constant
	ReqResAddFlags = 17

	// ReqResSubFlags  corresponds to the REQ_RES_SUB_FLAGS constant
	ReqResSubFlags = 18

	// ReqUnrestrict  corresponds to the REQ_UNRESTRICT constant
	ReqUnrestrict = 19

	// ReqMonGetList  corresponds to the REQ_MON_GETLIST constant
	ReqMonGetList = 20

	// ReqResetStats  corresponds to the REQ_RESET_STATS constant
	ReqResetStats = 21

	// ReqResetPeer  corresponds to the REQ_RESET_PEER constant
	ReqResetPeer = 22

	// ReqRereadKeys  corresponds to the REQ_REREAD_KEYS constant
	ReqRereadKeys = 23

	// ReqDoDirtyHack  corresponds to the REQ_DO_DIRTY_HACK constant
	ReqDoDirtyHack = 24

	// ReqDontDirtyHack  corresponds to the REQ_DONT_DIRTY_HACK constant
	ReqDontDirtyHack = 25

	// ReqTrustKey  corresponds to the REQ_TRUST_KEY constant
	ReqTrustKey = 26

	// ReqUntrustKey  corresponds to the REQ_UNTRUST_KEY constant
	ReqUntrustKey = 27

	// ReqAuthInfo  corresponds to the REQ_AUTH_INFO constant
	ReqAuthInfo = 28

	// ReqTraps  corresponds to the REQ_TRAPS constant
	ReqTraps = 29

	// ReqAddTrap  corresponds to the REQ_ADD_TRAP constant
	ReqAddTrap = 30

	// ReqClrTrap  corresponds to the REQ_CLR_TRAP constant
	ReqClrTrap = 31

	// ReqRequestKey  corresponds to the REQ_REQUEST_KEY constant
	ReqRequestKey = 32

	// ReqControlKey  corresponds to the REQ_CONTROL_KEY constant
	ReqControlKey = 33

	// ReqGetCtlStats  corresponds to the REQ_GET_CTLSTATS constant
	ReqGetCtlStats = 34

	// ReqGetLeapInfo  corresponds to the REQ_GET_LEAPINFO constant
	ReqGetLeapInfo = 35

	// ReqGetClockInfo  corresponds to the REQ_GET_CLOCKINFO constant
	ReqGetClockInfo = 36

	// ReqSetClkFudge  corresponds to the REQ_SET_CLKFUDGE constant
	ReqSetClkFudge = 37

	// ReqGetKernel  corresponds to the REQ_GET_KERNEL constant
	ReqGetKernel = 38

	// ReqGetClkBugInfo  corresponds to the REQ_GET_CLKBUGINFO constant
	ReqGetClkBugInfo = 39

	// ReqSetPrecision  corresponds to the REQ_SET_PRECISION constant
	ReqSetPrecision = 41

	// ReqMonGetList1  corresponds to the REQ_MON_GETLIST_1 constant
	ReqMonGetList1 = 42

	// ReqHostnameAssocID  corresponds to the REQ_HOSTNAME_ASSOCID constant
	ReqHostnameAssocID = 43

	// ReqIfStats  corresponds to the REQ_IF_STATS constant
	ReqIfStats = 44

	// ReqIfReload  corresponds to the REQ_IF_RELOAD constant
	ReqIfReload = 45
)

// These match the #defines in ntp-request.h
var requestCodeMap = map[string]RequestCode{
	"REQ_PEER_LIST":        ReqPeerList,
	"REQ_PEER_LIST_SUM":    ReqPeerListSum,
	"REQ_PEER_INFO":        ReqPeerInfo,
	"REQ_PEER_STATS":       ReqPeerStats,
	"REQ_SYS_INFO":         ReqSysInfo,
	"REQ_SYS_STATS":        ReqSysStats,
	"REQ_IO_STATS":         ReqIOStats,
	"REQ_MEM_STATS":        ReqMemStats,
	"REQ_LOOP_INFO":        ReqLoopInfo,
	"REQ_TIMER_STATS":      ReqTimerStats,
	"REQ_CONFIG":           ReqConfig,
	"REQ_UNCONFIG":         ReqUnconfig,
	"REQ_SET_SYS_FLAG":     ReqSetSysFlag,
	"REQ_CLR_SYS_FLAG":     ReqClrSysFlag,
	"REQ_MONITOR":          ReqMonitor,
	"REQ_NOMONITOR":        ReqNoMonitor,
	"REQ_GET_RESTRICT":     ReqGetRestrict,
	"REQ_RESADDFLAGS":      ReqResAddFlags,
	"REQ_RESSUBFLAGS":      ReqResSubFlags,
	"REQ_UNRESTRICT":       ReqUnrestrict,
	"REQ_MON_GETLIST":      ReqMonGetList,
	"REQ_RESET_STATS":      ReqResetStats,
	"REQ_RESET_PEER":       ReqResetPeer,
	"REQ_REREAD_KEYS":      ReqRereadKeys,
	"REQ_DO_DIRTY_HACK":    ReqDoDirtyHack,
	"REQ_DONT_DIRTY_HACK":  ReqDontDirtyHack,
	"REQ_TRUSTKEY":         ReqTrustKey,
	"REQ_UNTRUSTKEY":       ReqUntrustKey,
	"REQ_AUTHINFO":         ReqAuthInfo,
	"REQ_TRAPS":            ReqTraps,
	"REQ_ADD_TRAP":         ReqAddTrap,
	"REQ_CLR_TRAP":         ReqClrTrap,
	"REQ_REQUEST_KEY":      ReqRequestKey,
	"REQ_CONTROL_KEY":      ReqControlKey,
	"REQ_GET_CTLSTATS":     ReqGetCtlStats,
	"REQ_GET_LEAPINFO":     ReqGetLeapInfo,
	"REQ_GET_CLOCKINFO":    ReqGetClockInfo,
	"REQ_SET_CLKFUDGE":     ReqSetClkFudge,
	"REQ_GET_KERNEL":       ReqGetKernel,
	"REQ_GET_CLKBUGINFO":   ReqGetClkBugInfo,
	"REQ_SET_PRECISION":    ReqSetPrecision,
	"REQ_MON_GETLIST_1":    ReqMonGetList1,
	"REQ_HOSTNAME_ASSOCID": ReqHostnameAssocID,
	"REQ_IF_STATS":         ReqIfStats,
	"REQ_IF_RELOAD":        ReqIfReload,
}

var reverseRequestCodeMap map[RequestCode]string

// MarshalJSON gives the #define name, or "UNKNOWN (0x##)"
func (code RequestCode) MarshalJSON() ([]byte, error) {
	if reverseRequestCodeMap == nil {
		reverseRequestCodeMap = make(map[RequestCode]string)
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
func getRequestCode(enum string) (RequestCode, error) {
	ret, ok := requestCodeMap[enum]
	if ok {
		return ret, nil
	}
	v, err := strconv.ParseInt(enum, 0, 8)
	if err != nil {
		return 0, err
	}
	if v < 0 || v >= 0xff {
		return 0, ErrInvalidRequestCode
	}
	return RequestCode(v), nil
}

// InfoError is a 3-bit integer, values taken from ntp_request.h
type InfoError uint8

const (
	// InfoErrorOkay corresponds to the INFO_OKAY constant
	InfoErrorOkay InfoError = 0

	// InfoErrorImpl corresponds to the INFO_ERR_IMPL constant
	InfoErrorImpl = 1

	// InfoErrorReq corresponds to the INFO_ERR_REQ constant
	InfoErrorReq = 2

	// InfoErrorFmt corresponds to the INFO_ERR_FMT constant
	InfoErrorFmt = 3

	// InfoErrorNoData corresponds to the INFO_ERR_NODATA constant
	InfoErrorNoData = 4

	// InfoErrorUnknown5 has no corresponding constant (it is the unused value 5)
	InfoErrorUnknown5 = 5

	// InfoErrorUnknown6 has no corresponding constant (it is the unused value 6)
	InfoErrorUnknown6 = 6

	// InfoErrorAuth corresponds to the INFO_ERR_AUTH constant
	InfoErrorAuth = 7
)

// These match the #define names in ntp_rqeuest.h
var infoErrorMap = map[InfoError]string{
	InfoErrorOkay:   "INFO_OKAY",
	InfoErrorImpl:   "INFO_ERR_IMPL",
	InfoErrorReq:    "INFO_ERR_REQ",
	InfoErrorFmt:    "INFO_ERR_FMT",
	InfoErrorNoData: "INFO_ERR_NODATA",
	InfoErrorAuth:   "INFO_ERR_AUTH",
}

// isInfoError checks if err is an instance of InfoError
func isInfoError(err error) bool {
	_, ok := err.(InfoError)
	return ok
}

// Error implements the error interface (returns the #define name, or "UNKNOWN (0x##)")
func (err InfoError) Error() string {
	ret, ok := infoErrorMap[err]
	if !ok {
		return fmt.Sprintf("UNKNOWN (0x%02x)", uint8(err))
	}
	return ret
}

// MarshalJSON gives the #define name, or "UNKNOWN (0x##)"
func (err InfoError) MarshalJSON() ([]byte, error) {
	return json.Marshal(err.Error())
}

// NTPShort a 32-bit struct defined in figure 3 of RFC5905.
type NTPShort struct {
	Seconds  uint16 `json:"seconds"`
	Fraction uint16 `json:"fraction"`
}

// Decode populates the values of this NTPShort with the first 4 bytes of buf
func (when *NTPShort) Decode(buf []byte) error {
	if len(buf) < 4 {
		return ErrBufferTooSmall
	}
	when.Seconds = binary.BigEndian.Uint16(buf[0:2])
	when.Fraction = binary.BigEndian.Uint16(buf[2:4])
	return nil
}

// decodeNTPShort decodes an NTPShort from the first 4 bytes of buf
func decodeNTPShort(buf []byte) (*NTPShort, error) {
	if len(buf) < 4 {
		return nil, ErrBufferTooSmall
	}
	ret := NTPShort{}
	err := ret.Decode(buf)
	return &ret, err
}

// Encode encodes the NTPShort according to RFC5905 -- upper 16 bits the seconds, lower 16 bits the fractional seconds (big endian)
func (when *NTPShort) Encode() []byte {
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

// GetNanos gets the number of nanoseconds represented by when.Fraction
func (when *NTPShort) GetNanos() uint32 {
	return uint32(uint16FracToNanos * float32(when.Fraction))
}

// SetNanos sets when.Fraction to the binary fractional value corresponding to nanos nanoseconds
func (when *NTPShort) SetNanos(nanos int) {
	when.Fraction = uint16(nanosToUint16Frac * float32(nanos))
}

// GetDuration gets the time.Duration corresponding to when
func (when *NTPShort) GetDuration() time.Duration {
	return time.Duration(when.Seconds)*time.Second + time.Duration(when.GetNanos())*time.Nanosecond
}

// SetDuration sets the Seconds and Fraction to match the given duration
func (when *NTPShort) SetDuration(d time.Duration) {
	ns := d.Nanoseconds()
	when.Seconds = uint16(ns / 1e9)
	when.SetNanos(int(ns % 1e9))
}

// NTPLong is a 64-bit fixed-length number defined in figure 3 of RFC5905
type NTPLong struct {
	Seconds  uint32 `json:"seconds"`
	Fraction uint32 `json:"fraction"`
}

// GetNanos gets the number of nanoseconds represented by when.Fraction
func (when *NTPLong) GetNanos() uint64 {
	return uint64(uint32FracToNanos * float64(when.Fraction))
}

// SetNanos sets when.Fraction to the binary fractional value corresponding to nanos nanoseconds
func (when *NTPLong) SetNanos(nanos int) {
	when.Fraction = uint32(nanosToUint32Frac * float64(nanos))
}

// GetTime gets the absolute time.Time corresponding to when
func (when *NTPLong) GetTime() time.Time {
	return ntpEpoch.Add(time.Duration(when.Seconds)*time.Second + time.Duration(when.GetNanos())*time.Nanosecond)
}

// SetTime sets the absolute time.Time
func (when *NTPLong) SetTime(t time.Time) {
	ntpTime := t.Add(unixEpoch.Sub(ntpEpoch))
	// whole seconds
	s := ntpTime.Unix()
	// fractional nanoseconds
	ns := ntpTime.UnixNano() - s*1e9
	when.Seconds = uint32(s)
	when.SetNanos(int(ns))
}

// Decode populates the values of this NTPShort with the first 8 bytes of buf
func (when *NTPLong) Decode(buf []byte) error {
	if len(buf) < 8 {
		return ErrBufferTooSmall
	}
	when.Seconds = binary.BigEndian.Uint32(buf[0:4])
	when.Fraction = binary.BigEndian.Uint32(buf[4:8])
	return nil
}

// decodeNTPLong decodes an NTPShort from the first 8 bytes of buf
func decodeNTPLong(buf []byte) (*NTPLong, error) {
	if len(buf) < 8 {
		return nil, ErrBufferTooSmall
	}
	ret := NTPLong{}
	err := ret.Decode(buf)
	return &ret, err
}

// Encode encodes the NTPShort according to RFC5905 -- upper 32 bits the seconds, lower 32 bits the fractional seconds (big endian)
func (when *NTPLong) Encode() []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint32(ret[0:4], when.Seconds)
	binary.BigEndian.PutUint32(ret[4:8], when.Fraction)
	return ret
}

// ReferenceID is defined in RFC5905 as a 32-bit code whose interpretation depends on the stratum field
type ReferenceID [4]byte

// MarshalJSON ensures that it is marshalled like a slice, not an array
func (id ReferenceID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id[:])
}

// NTPHeader is defined in figure 8 of RFC5905
type NTPHeader struct {
	// LeapIndicator is the the top two bits of the first byte
	LeapIndicator LeapIndicator `json:"leap_indicator"`

	// Version is bits 5..3 of the first byte
	Version uint8 `json:"version"`

	// The mode is the lowest three bits of the first byte
	Mode AssociationMode `json:"mode"`

	// Stratum is defined in figure 11: values > 16 are Reserved
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

	// Reference ID (refid): 32-bit code identifying the particular Server or reference clock.
	ReferenceID ReferenceID `json:"reference_id,omitempty"`

	// Reference Timestamp: Time when the system clock was last set or corrected
	ReferenceTimestamp NTPLong `json:"reference_timestamp,omitempty"`

	// Origin Timestamp (org): Time at the Client when the request departed for the Server
	OriginTimestamp NTPLong `json:"origin_timestamp,omitempty"`

	// Receive Timestamp (rec): Time at the Server when the request arrived from the Client
	ReceiveTimestamp NTPLong `json:"receive_timestamp,omitempty"`

	// Transmit Timestamp (xmt): Time at the Server when the response left for the Client
	TransmitTimestamp NTPLong `json:"transmit_timestamp,omitempty"`
}

// decodeNTPHeader decodes an NTP header from the first 48 bytes of buf
func decodeNTPHeader(buf []byte) (*NTPHeader, error) {
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

// readNTPHeader reads 48 bytes from conn and interprets it as an NTPHeader
func readNTPHeader(conn net.Conn) (*NTPHeader, error) {
	buf := make([]byte, 48)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return decodeNTPHeader(buf)
}

// Encode returns the encoding of the header according to RFC5905
func (header *NTPHeader) Encode() ([]byte, error) {
	ret := make([]byte, 48)
	if (header.Version >> 3) != 0 {
		return nil, ErrInvalidVersion
	}
	if (header.Mode >> 3) != 0 {
		return nil, ErrInvalidMode
	}
	if (header.LeapIndicator >> 2) != 0 {
		return nil, ErrInvalidLeapIndicator
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

// ValidateSyntax checks that the header's values are within range and make semantic sense
func (header *NTPHeader) ValidateSyntax() error {
	if header.Version < 1 || header.Version > 4 {
		return ErrInvalidVersion
	}
	if header.Mode == 0 {
		return ErrInvalidMode
	}
	if header.Stratum > 16 {
		return ErrInvalidStratum
	}
	if header.Stratum < 2 {
		// For packet stratum 0 [the reference ID] is a four-character ASCII string
		// called the "kiss code"... For stratum 1 (reference clock), this is a
		// four-octet, left-justified, zero-padded ASCII string
		for _, v := range header.ReferenceID {
			if v >= 0x7f {
				return ErrInvalidReferenceID
			}
		}
	}
	return nil
}

// PrivatePacketHeader represents a header for a mode-7 packet, roughly corresponding to struct resp_pkt in ntp_request.h
type PrivatePacketHeader struct {
	IsResponse           bool            `json:"is_response"`
	HasMore              bool            `json:"has_more"`
	Version              uint8           `json:"version"`
	Mode                 AssociationMode `json:"mode"`
	IsAuthenticated      bool            `json:"is_authenticated"`
	SequenceNumber       uint8           `json:"sequence_number"`
	ImplementationNumber ImplNumber      `json:"implementation_number"`
	RequestCode          RequestCode     `json:"request_code"`
	Error                InfoError       `json:"error"`
	NumItems             uint16          `json:"num_items"`
	MBZ                  uint8           `json:"mbz"`
	ItemSize             uint16          `json:"item_size"`
}

// Encode encodes the packet header as a struct resp_pkt
func (header *PrivatePacketHeader) Encode() ([]byte, error) {
	ret := [8]byte{}
	if (header.Mode>>3) != 0 || (header.Version>>3) != 0 {
		return nil, ErrInvalidHeader
	}
	ret[0] = uint8(header.Mode) | (header.Version << 3)
	if header.IsResponse {
		ret[0] = ret[0] | 0x80
	}
	if header.HasMore {
		ret[0] = ret[0] | 0x40
	}
	if header.SequenceNumber&0x80 != 0 {
		return nil, ErrInvalidHeader
	}
	ret[1] = header.SequenceNumber
	if header.IsAuthenticated {
		ret[1] = ret[1] | 0x80
	}
	ret[2] = uint8(header.ImplementationNumber)
	ret[3] = uint8(header.RequestCode)
	if (header.Error>>4) != 0 || (header.NumItems>>12) != 0 {
		return nil, ErrInvalidHeader
	}
	ret[4] = (uint8(header.Error) << 4) | uint8(header.NumItems>>8)
	ret[5] = byte(header.NumItems & 0xFF)
	if (header.MBZ>>4) != 0 || (header.ItemSize>>12) != 0 {
		return nil, ErrInvalidHeader
	}
	ret[6] = (header.MBZ << 4) | uint8(header.ItemSize>>8)
	ret[7] = byte(header.ItemSize & 0xFF)
	return ret[:], nil
}

// Decode a Private packet header from the first 8 bytes of buf
func decodePrivatePacketHeader(buf []byte) (*PrivatePacketHeader, error) {
	ret := PrivatePacketHeader{}
	if len(buf) < 8 {
		return nil, ErrInvalidHeader
	}
	ret.Mode = AssociationMode(buf[0] & 0x07)
	ret.Version = buf[0] >> 3 & 0x07
	ret.HasMore = (buf[0]>>6)&1 == 1
	ret.IsResponse = (buf[0]>>7)&1 == 1
	ret.SequenceNumber = buf[1] & 0x7F
	ret.IsAuthenticated = (buf[1]>>7)&1 == 1
	ret.ImplementationNumber = ImplNumber(buf[2])
	ret.RequestCode = RequestCode(buf[3])
	ret.Error = InfoError(buf[4] >> 4)
	ret.NumItems = uint16(buf[4]&0x0F)<<4 | uint16(buf[5])
	ret.MBZ = buf[6] >> 4
	ret.ItemSize = uint16(buf[6]&0x0f)<<4 | uint16(buf[7])
	return &ret, nil
}

// Results is the struct that is returned to the zgrab2 framework from Scan()
type Results struct {
	// Version is the version number returned in the get time response header.
	// Absent if --skip-get-time is set.
	Version *uint8 `json:"version,omitempty"`

	// Time is the time returned by the server (specifically, the
	// ReceiveTimestamp) in response to the get time call. Converted into a
	// standard golang time.
	// Absent if --skip-get-time is set.
	Time *time.Time `json:"time,omitempty"`

	// TimeResponse is the full header returned by the get time call.
	// Absent if --skip-get-time is set. Debug only.
	TimeResponse *NTPHeader `json:"time_response,omitempty" zgrab:"debug"`

	// MonListResponse is the raw data returned by the call to monlist.
	// Only present if --monlist is set.
	MonListResponse []byte `json:"monlist_response,omitempty"`

	// MonListHeader is the header returned by the call to monlist.
	// Only present if --monlist is set. Debug only.
	MonListHeader *PrivatePacketHeader `json:"monlist_header,omitempty" zgrab:"debug"`
}

// Flags holds the command-line flags for the scanner.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.UDPFlags
	Verbose       bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	Version       uint8  `long:"version" description:"The version number to pass to the Server." default:"3"`
	LeapIndicator uint8  `long:"leap-indicator" description:"The LI value to pass to the Server. Default 3 (Unknown)"`
	SkipGetTime   bool   `long:"skip-get-time" description:"If set, don't request the Server time"`
	MonList       bool   `long:"monlist" description:"Perform a ReqMonGetList request"`
	RequestCode   string `long:"request-code" description:"Specify a request code for MonList other than ReqMonGetList" default:"REQ_MON_GETLIST"`
}

// Module is the zgrab2 module implementation
type Module struct {
}

// Scanner holds the state for a single scan
type Scanner struct {
	config *Flags
}

// RegisterModule registers the module with zgrab2
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("ntp", "NTP", module.Description(), 123, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a flags instant to be populated with the command line args
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new NTP scanner instance
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Scan for NTP"
}

// Validate checks that the flags are valid
func (cfg *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string
func (cfg *Flags) Help() string {
	return ""
}

// Init initialized the scanner
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

// InitPerSender initializes the scanner for a given sender
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// Protocol returns the protocol identifer for the scanner.
func (s *Scanner) Protocol() string {
	return "ntp"
}

// GetName returns the module's name
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// SendAndReceive is a rough version of ntpdc.c's doquery(), except it only supports a single packet response
func (scanner *Scanner) SendAndReceive(impl ImplNumber, req RequestCode, body []byte, sock net.Conn) (*PrivatePacketHeader, []byte, error) {
	outHeader, err := (&PrivatePacketHeader{
		Version:              scanner.config.Version,
		Mode:                 Private,
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
	if inPacket.Mode != Private {
		log.Debugf("Received non Private-mode packet (mode=0x%02x), packet=%v", inPacket.Mode, inPacket)
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
	if inPacket.Error != InfoErrorOkay {
		log.Debugf("Got error in non-final response packet (error=0x%02x), packet=%v", inPacket.Error, inPacket)
		return inPacket, nil, inPacket.Error
	}
	ret := response[8:]
	if len(ret) != int(inPacket.ItemSize*inPacket.NumItems) {
		log.Debugf("Body length (%d) does not match record size (%d) * num records (%d)", len(ret), inPacket.ItemSize, inPacket.NumItems)
		return inPacket, ret, ErrInvalidResponse
	}
	return inPacket, ret, nil
}

// MonList does a ReqMonGetList call to the Server and populates result with the output
func (scanner *Scanner) MonList(sock net.Conn, result *Results) (zgrab2.ScanStatus, error) {
	ReqCode, err := getRequestCode(scanner.config.RequestCode)
	if err != nil {
		panic(err)
	}
	body := make([]byte, 40)
	header, ret, err := scanner.SendAndReceive(ImplXNTPD, ReqCode, body, sock)
	if ret != nil {
		result.MonListResponse = ret
	}
	if header != nil {
		result.MonListHeader = header
	}
	if err != nil {
		switch {
		case err == ErrInvalidResponse:
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

// GetTime sends a "Client" packet to the Server and reads / returns the response
func (scanner *Scanner) GetTime(sock net.Conn) (*NTPHeader, error) {
	outPacket := NTPHeader{}
	outPacket.Mode = Client
	outPacket.Version = scanner.config.Version
	outPacket.LeapIndicator = LeapIndicator(scanner.config.LeapIndicator)
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

// Scan scans the configured server with the settings provided by the command
// line arguments as follows:
//  1. If SkipGetTime is not set, send a GetTime packet to the server and read
//     the response packet into the result.
//  2. If MonList is set, send a MONLIST packet to the server and read the
//     response packet into the result.
//
// The presence of an NTP service at the target can be inferred by a non-nil
// result -- if the service does not return any data or if the response is not
// a valid NTP packet, then the result will be nil.
// The presence of a DDoS-amplifying target can be inferred by
// result.MonListReponse being present.
func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	sock, err := t.OpenUDP(&scanner.config.BaseFlags, &scanner.config.UDPFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer sock.Close()
	result := &Results{}
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
