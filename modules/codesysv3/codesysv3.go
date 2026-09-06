package codesysv3

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf16"
)

// CODESYS V3 runtimes expose a "NameService" that answers a ResolveAddr
// request with an Identification packet describing the device (vendor,
// device/node name, target type/id/version, serial number, ...). This is
// the same mechanism used by Rapid7's codesys3.lua and nmap's
// codesys-plc-info script.
//
// Two wire transports carry the same NameService datagram:
//   - TCP: the datagram is wrapped in an 8-byte CmpBlkDrvTcp header
//     (magic uint32 LE, then total length uint32 LE) and addressed
//     absolutely (sender/receiver are full IP:port pairs). Usually TCP/11740-11743.
//   - UDP: the datagram is sent unwrapped, addressed relative to the
//     local subnet (a masked IP octet + a 2-bit port index folded into a
//     single sender word). Usually UDP/1740-1743.
const (
	nsMagic           byte   = 0xC5
	nsRequest         byte   = 0x03
	nsResponse        byte   = 0x04
	pkgResolveAddr    uint16 = 0xC202
	pkgIdentification uint16 = 0xC280
	nodeInfoVersion   uint16 = 0x0400
	tcpBDMagic        uint32 = 0xe8170100
)

var (
	ErrNoMagic          = errors.New("no CODESYS V3 NameService datagram magic found")
	ErrNotResponse      = errors.New("not a CODESYS V3 NameService response")
	ErrUnexpectedPkg    = errors.New("unexpected CODESYS V3 package type")
	ErrUnsupportedVer   = errors.New("unsupported CODESYS V3 NodeInfo version")
	ErrPayloadTruncated = errors.New("CODESYS V3 NameService payload truncated")
	ErrBodyTruncated    = errors.New("CODESYS V3 identification body truncated")
	ErrRequiresIPv4     = errors.New("CODESYS V3 addressing requires an IPv4 address")
)

// DeviceInfo is the JSON-serializable result of a CODESYS V3 scan.
type DeviceInfo struct {
	VendorName       string `json:"vendor_name,omitempty"`
	DeviceName       string `json:"device_name,omitempty"`
	NodeName         string `json:"node_name,omitempty"`
	SerialNumber     string `json:"serial_number,omitempty"`
	TargetType       uint32 `json:"target_type"`
	TargetID         uint32 `json:"target_id"`
	TargetVersion    uint32 `json:"target_version"`
	TargetVersionStr string `json:"target_version_str,omitempty"`
	Flags            uint32 `json:"flags"`
	MaxChannels      uint16 `json:"max_channels"`
	IntelByteOrder   bool   `json:"intel_byte_order"`
	BlkDrvType       uint8  `json:"blk_drv_type"`
	RequestID        uint32 `json:"request_id"`
}

func versionString(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", (v>>24)&0xff, (v>>16)&0xff, (v>>8)&0xff, v&0xff)
}

// utf16leString decodes a UTF-16LE byte string, trimming the trailing NUL
// terminator(s) CODESYS pads these fields with.
func utf16leString(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}
	return strings.TrimSpace(strings.TrimRight(string(utf16.Decode(units)), "\x00"))
}

// tcpAddrBytes encodes a port + IPv4 address the way CmpBlkDrvTcp addressing expects: 2 bytes big-endian port, then 4 raw IPv4 octets.
func tcpAddrBytes(ip net.IP, port uint16) ([]byte, error) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, ErrRequiresIPv4
	}
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], port)
	copy(buf[2:6], v4)
	return buf, nil
}

// BuildTCPResolveRequest builds a TCP CmpBlkDrvTcp-framed NameService
// ResolveAddr request between localAddr and remoteAddr (both must be IPv4).
func BuildTCPResolveRequest(localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16, broadcastID uint16, requestID uint32) ([]byte, error) {
	localAddrBytes, err := tcpAddrBytes(localIP, localPort)
	if err != nil {
		return nil, err
	}
	remoteAddrBytes, err := tcpAddrBytes(remoteIP, remotePort)
	if err != nil {
		return nil, err
	}

	const hopinfo = ((0x0f & 0x1f) << 3) | (4 & 7) // header_length=4 words
	const packetinfo = ((1 & 3) << 6) | (1 << 4)   // absolute addressing
	const addressLengths = 0x33                    // 3 sender words, 3 receiver words

	datagram := make([]byte, 8, 8+len(localAddrBytes)+len(remoteAddrBytes)+8)
	datagram[0] = nsMagic
	datagram[1] = hopinfo
	datagram[2] = packetinfo
	datagram[3] = nsRequest
	datagram[4] = 0x00
	datagram[5] = addressLengths
	binary.BigEndian.PutUint16(datagram[6:8], broadcastID)
	datagram = append(datagram, localAddrBytes...)
	datagram = append(datagram, remoteAddrBytes...)
	if pad := len(datagram) % 4; pad != 0 {
		datagram = append(datagram, make([]byte, 4-pad)...)
	}

	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], pkgResolveAddr)
	binary.LittleEndian.PutUint16(payload[2:4], nodeInfoVersion)
	binary.LittleEndian.PutUint32(payload[4:8], requestID)
	datagram = append(datagram, payload...)

	total := uint32(8 + len(datagram))
	packet := make([]byte, 8, 8+len(datagram))
	binary.LittleEndian.PutUint32(packet[0:4], tcpBDMagic)
	binary.LittleEndian.PutUint32(packet[4:8], total)
	return append(packet, datagram...), nil
}

// BuildUDPResolveRequest builds a UDP NameService ResolveAddr request.
// portIndex identifies which of the 4 UDP instances (1740-1743) is being
// queried and is folded into the sender address, along with the local IP
// masked to netmaskCIDR, per the wire format used by codesys3.lua.
func BuildUDPResolveRequest(localIP net.IP, portIndex int, netmaskCIDR int, broadcastID uint16, requestID uint32) ([]byte, error) {
	v4 := localIP.To4()
	if v4 == nil {
		return nil, ErrRequiresIPv4
	}

	localBits := 32 - netmaskCIDR
	if localBits < 0 {
		localBits = 0
	} else if localBits > 32 {
		localBits = 32
	}
	const portBits = 2
	senderWords := (localBits + portBits + 15) / 16
	if senderWords > 0xF {
		senderWords = 0xF
	}
	addressLengths := byte((senderWords & 0xF) << 4)

	myAddress := binary.BigEndian.Uint32(v4)
	var mask uint32
	if localBits < 32 {
		mask = (uint32(1) << uint(localBits)) - 1
	} else {
		mask = 0xFFFFFFFF
	}
	senderAddress := (uint32(portIndex&3) << uint(localBits)) | (myAddress & mask)

	const hopinfo = ((0x0f & 0x1f) << 3) | (4 & 7) // header_length=4 words
	const packetinfo = (1 & 3) << 6                // relative/broadcast addressing

	header := make([]byte, 8, 16)
	header[0] = nsMagic
	header[1] = hopinfo
	header[2] = packetinfo
	header[3] = nsRequest
	header[4] = 0x00
	header[5] = addressLengths
	binary.BigEndian.PutUint16(header[6:8], broadcastID)

	for i := 0; i < senderWords; i++ {
		shift := uint(16 * (senderWords - 1 - i))
		word := make([]byte, 2)
		binary.BigEndian.PutUint16(word, uint16((senderAddress>>shift)&0xffff))
		header = append(header, word...)
	}
	if pad := len(header) % 4; pad != 0 {
		header = append(header, make([]byte, 4-pad)...)
	}

	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], pkgResolveAddr)
	binary.LittleEndian.PutUint16(payload[2:4], nodeInfoVersion)
	binary.LittleEndian.PutUint32(payload[4:8], requestID)
	return append(header, payload...), nil
}

// ParseResponse validates and decodes a NameService Identification response
// (NodeInfo version 4.00), peeling the optional TCP block-driver framing
// first if present.
func ParseResponse(data []byte) (*DeviceInfo, error) {
	if len(data) == 0 {
		return nil, ErrNoMagic
	}

	offset := 0
	if len(data) >= 8 && binary.LittleEndian.Uint32(data[:4]) == tcpBDMagic {
		offset = 8
	}

	view := data[offset:]
	c5 := bytes.IndexByte(view, nsMagic)
	if c5 < 0 || c5+6 > len(view) {
		return nil, ErrNoMagic
	}
	view = view[c5:]

	hopinfo := view[1]
	serviceID := view[3]
	addressLengths := view[5]
	if serviceID != nsResponse {
		return nil, ErrNotResponse
	}

	headerLength := int(hopinfo & 7)
	pos := headerLength*2 + int(addressLengths&0xF)*2 + int((addressLengths>>4)&0xF)*2
	if r := pos % 4; r != 0 {
		pos += 4 - r
	}
	if pos+8 > len(view) {
		return nil, ErrPayloadTruncated
	}

	packageType := binary.LittleEndian.Uint16(view[pos : pos+2])
	version := binary.LittleEndian.Uint16(view[pos+2 : pos+4])
	requestID := binary.LittleEndian.Uint32(view[pos+4 : pos+8])
	pos += 8
	if packageType != pkgIdentification {
		return nil, ErrUnexpectedPkg
	}
	if version != nodeInfoVersion {
		return nil, ErrUnsupportedVer
	}
	// Structured fields before the variable-length string table (~39 bytes).
	if pos+39 > len(view) {
		return nil, ErrBodyTruncated
	}

	maxChannels := binary.LittleEndian.Uint16(view[pos : pos+2])
	intelByteOrder := view[pos+2]
	parentAddrSize := binary.LittleEndian.Uint16(view[pos+4 : pos+6])
	pos += 6

	nodeNameLen := int(binary.LittleEndian.Uint16(view[pos : pos+2]))
	deviceNameLen := int(binary.LittleEndian.Uint16(view[pos+2 : pos+4]))
	vendorNameLen := int(binary.LittleEndian.Uint16(view[pos+4 : pos+6]))
	pos += 6

	targetType := binary.LittleEndian.Uint32(view[pos : pos+4])
	targetID := binary.LittleEndian.Uint32(view[pos+4 : pos+8])
	targetVersion := binary.LittleEndian.Uint32(view[pos+8 : pos+12])
	flags := binary.LittleEndian.Uint32(view[pos+12 : pos+16])
	pos += 16

	serialLen := int(view[pos])
	oemLen := int(view[pos+1])
	blkDrvType := view[pos+2]
	pos += 3
	pos += 1 + 8 // 1 pad byte + 8 reserved bytes

	take := func(n int) ([]byte, error) {
		if n < 0 || pos+n > len(view) {
			return nil, ErrBodyTruncated
		}
		b := view[pos : pos+n]
		pos += n
		return b, nil
	}

	if _, err := take(int(parentAddrSize)); err != nil {
		return nil, err
	}
	nodeNameBytes, err := take(nodeNameLen * 2)
	if err != nil {
		return nil, err
	}
	pos += 2 // NUL terminator
	deviceNameBytes, err := take(deviceNameLen * 2)
	if err != nil {
		return nil, err
	}
	pos += 2
	vendorNameBytes, err := take(vendorNameLen * 2)
	if err != nil {
		return nil, err
	}
	pos += 2
	serialBytes, err := take(serialLen)
	if err != nil {
		return nil, err
	}
	pos += 1
	if _, err := take(oemLen); err != nil {
		return nil, err
	}

	return &DeviceInfo{
		VendorName:       utf16leString(vendorNameBytes),
		DeviceName:       utf16leString(deviceNameBytes),
		NodeName:         utf16leString(nodeNameBytes),
		SerialNumber:     strings.TrimRight(string(serialBytes), "\x00"),
		TargetType:       targetType,
		TargetID:         targetID,
		TargetVersion:    targetVersion,
		TargetVersionStr: versionString(targetVersion),
		Flags:            flags,
		MaxChannels:      maxChannels,
		IntelByteOrder:   intelByteOrder != 0,
		BlkDrvType:       blkDrvType,
		RequestID:        requestID,
	}, nil
}
