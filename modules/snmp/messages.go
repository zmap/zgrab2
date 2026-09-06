package snmp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	tagInteger       = 0x02
	tagOctetString   = 0x04
	tagNull          = 0x05
	tagObjectID      = 0x06
	tagSequence      = 0x30
	tagGetRequest    = 0xa0
	tagGetResponse   = 0xa2
	tagReport        = 0xa8
	tagIPAddress     = 0x40
	tagCounter32     = 0x41
	tagGauge32       = 0x42
	tagTimeTicks     = 0x43
	tagOpaque        = 0x44
	tagNoSuchObject  = 0x80
	tagNoSuchInst    = 0x81
	tagEndOfMIBView  = 0x82
	tagTrapV2        = 0xa7
	tagInformRequest = 0xa6
)

var (
	errInvalidSNMP = errors.New("invalid SNMP response")
	systemOIDs     = []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr.0
		"1.3.6.1.2.1.1.2.0", // sysObjectID.0
		"1.3.6.1.2.1.1.3.0", // sysUpTime.0
		"1.3.6.1.2.1.1.4.0", // sysContact.0
		"1.3.6.1.2.1.1.5.0", // sysName.0
		"1.3.6.1.2.1.1.6.0", // sysLocation.0
		"1.3.6.1.2.1.1.7.0", // sysServices.0
	}
	oidNames = map[string]string{
		"1.3.6.1.2.1.1.1.0": "sys_descr",
		"1.3.6.1.2.1.1.2.0": "sys_object_id",
		"1.3.6.1.2.1.1.3.0": "sys_uptime",
		"1.3.6.1.2.1.1.4.0": "sys_contact",
		"1.3.6.1.2.1.1.5.0": "sys_name",
		"1.3.6.1.2.1.1.6.0": "sys_location",
		"1.3.6.1.2.1.1.7.0": "sys_services",
	}
)

type tlv struct {
	tag   byte
	value []byte
}

func BuildGetRequest(version, community string, oids []string) ([]byte, error) {
	versionValue, err := snmpVersionNumber(version)
	if err != nil {
		return nil, err
	}

	var varbinds [][]byte
	for _, oid := range oids {
		encodedOID, err := encodeOID(oid)
		if err != nil {
			return nil, err
		}
		varbind := wrap(tagSequence, append(wrap(tagObjectID, encodedOID), wrap(tagNull, nil)...))
		varbinds = append(varbinds, varbind)
	}

	var varbindList []byte
	for _, varbind := range varbinds {
		varbindList = append(varbindList, varbind...)
	}

	pdu := wrap(tagGetRequest, concat(
		wrap(tagInteger, encodeInteger(1)),
		wrap(tagInteger, encodeInteger(0)),
		wrap(tagInteger, encodeInteger(0)),
		wrap(tagSequence, varbindList),
	))

	return wrap(tagSequence, concat(
		wrap(tagInteger, encodeInteger(versionValue)),
		wrap(tagOctetString, []byte(community)),
		pdu,
	)), nil
}

func BuildV3DiscoveryRequest() []byte {
	msgID := 1
	headerData := wrap(tagSequence, concat(
		wrap(tagInteger, encodeInteger(msgID)),
		wrap(tagInteger, encodeInteger(65507)),
		wrap(tagOctetString, []byte{0x04}), // reportable, noAuthNoPriv
		wrap(tagInteger, encodeInteger(3)), // USM
	))
	securityParameters := wrap(tagSequence, concat(
		wrap(tagOctetString, nil), // authoritative engine ID
		wrap(tagInteger, encodeInteger(0)),
		wrap(tagInteger, encodeInteger(0)),
		wrap(tagOctetString, nil), // user
		wrap(tagOctetString, nil), // auth params
		wrap(tagOctetString, nil), // priv params
	))
	scopedPDU := wrap(tagSequence, concat(
		wrap(tagOctetString, nil), // context engine ID
		wrap(tagOctetString, nil), // context name
		wrap(tagGetRequest, concat(
			wrap(tagInteger, encodeInteger(msgID)),
			wrap(tagInteger, encodeInteger(0)),
			wrap(tagInteger, encodeInteger(0)),
			wrap(tagSequence, nil),
		)),
	))
	return wrap(tagSequence, concat(
		wrap(tagInteger, encodeInteger(3)),
		headerData,
		wrap(tagOctetString, securityParameters),
		scopedPDU,
	))
}

func BuildV2Trap(community string) []byte {
	sysUptimeOID, _ := encodeOID("1.3.6.1.2.1.1.3.0")
	trapOIDOID, _ := encodeOID("1.3.6.1.6.3.1.1.4.1.0")
	coldStartOID, _ := encodeOID("1.3.6.1.6.3.1.1.5.1")

	varbindList := concat(
		wrap(tagSequence, concat(
			wrap(tagObjectID, sysUptimeOID),
			wrap(tagTimeTicks, encodeInteger(0)),
		)),
		wrap(tagSequence, concat(
			wrap(tagObjectID, trapOIDOID),
			wrap(tagObjectID, coldStartOID),
		)),
	)

	pdu := wrap(tagTrapV2, concat(
		wrap(tagInteger, encodeInteger(1)),
		wrap(tagInteger, encodeInteger(0)),
		wrap(tagInteger, encodeInteger(0)),
		wrap(tagSequence, varbindList),
	))

	return wrap(tagSequence, concat(
		wrap(tagInteger, encodeInteger(1)), // version = 2c
		wrap(tagOctetString, []byte(community)),
		pdu,
	))
}

func BuildInformRequest(community string) []byte {
	sysUptimeOID, _ := encodeOID("1.3.6.1.2.1.1.3.0")
	trapOIDOID, _ := encodeOID("1.3.6.1.6.3.1.1.4.1.0")
	coldStartOID, _ := encodeOID("1.3.6.1.6.3.1.1.5.1")

	varbindList := concat(
		wrap(tagSequence, concat(
			wrap(tagObjectID, sysUptimeOID),
			wrap(tagTimeTicks, encodeInteger(0)),
		)),
		wrap(tagSequence, concat(
			wrap(tagObjectID, trapOIDOID),
			wrap(tagObjectID, coldStartOID),
		)),
	)

	pdu := wrap(tagInformRequest, concat(
		wrap(tagInteger, encodeInteger(1)),
		wrap(tagInteger, encodeInteger(0)),
		wrap(tagInteger, encodeInteger(0)),
		wrap(tagSequence, varbindList),
	))

	return wrap(tagSequence, concat(
		wrap(tagInteger, encodeInteger(1)), // version = 2c
		wrap(tagOctetString, []byte(community)),
		pdu,
	))
}

func ParseResponse(b []byte) (*Log, error) {
	msg, rest, err := readTLV(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || msg.tag != tagSequence {
		return nil, errInvalidSNMP
	}

	children, err := readTLVs(msg.value)
	if err != nil {
		return nil, err
	}
	if len(children) != 3 || children[0].tag != tagInteger || children[1].tag != tagOctetString || children[2].tag != tagGetResponse {
		return nil, errInvalidSNMP
	}

	pduChildren, err := readTLVs(children[2].value)
	if err != nil {
		return nil, err
	}
	if len(pduChildren) != 4 || pduChildren[0].tag != tagInteger || pduChildren[1].tag != tagInteger || pduChildren[2].tag != tagInteger || pduChildren[3].tag != tagSequence {
		return nil, errInvalidSNMP
	}

	ret := &Log{
		RequestID:   decodeInteger(pduChildren[0].value),
		ErrorStatus: decodeInteger(pduChildren[1].value),
		ErrorIndex:  decodeInteger(pduChildren[2].value),
		Values:      map[string]string{},
	}

	varbinds, err := readTLVs(pduChildren[3].value)
	if err != nil {
		return nil, err
	}
	for _, varbind := range varbinds {
		if varbind.tag != tagSequence {
			return nil, errInvalidSNMP
		}
		pair, err := readTLVs(varbind.value)
		if err != nil {
			return nil, err
		}
		if len(pair) != 2 || pair[0].tag != tagObjectID {
			return nil, errInvalidSNMP
		}
		oid, err := decodeOID(pair[0].value)
		if err != nil {
			return nil, err
		}
		value := formatValue(pair[1])
		name, ok := oidNames[oid]
		if !ok {
			name = oid
		}
		ret.Values[name] = value
		switch name {
		case "sys_descr":
			ret.SysDescr = value
		case "sys_object_id":
			ret.SysObjectID = value
		case "sys_uptime":
			ret.SysUpTime = value
		case "sys_contact":
			ret.SysContact = value
		case "sys_name":
			ret.SysName = value
		case "sys_location":
			ret.SysLocation = value
		case "sys_services":
			if n, err := strconv.Atoi(value); err == nil {
				ret.SysServices = n
			}
		}
	}
	return ret, nil
}

func ParseV3DiscoveryResponse(b []byte) (*Log, error) {
	msg, rest, err := readTLV(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || msg.tag != tagSequence {
		return nil, errInvalidSNMP
	}
	children, err := readTLVs(msg.value)
	if err != nil {
		return nil, err
	}
	if len(children) != 4 || children[0].tag != tagInteger || children[1].tag != tagSequence || children[2].tag != tagOctetString {
		return nil, errInvalidSNMP
	}
	if decodeInteger(children[0].value) != 3 {
		return nil, errInvalidSNMP
	}

	header, err := readTLVs(children[1].value)
	if err != nil {
		return nil, err
	}
	ret := &Log{Values: map[string]string{}}
	if len(header) >= 1 && header[0].tag == tagInteger {
		ret.RequestID = decodeInteger(header[0].value)
	}

	security, rest, err := readTLV(children[2].value)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || security.tag != tagSequence {
		return nil, errInvalidSNMP
	}
	usm, err := readTLVs(security.value)
	if err != nil {
		return nil, err
	}
	if len(usm) >= 3 && usm[0].tag == tagOctetString && usm[1].tag == tagInteger && usm[2].tag == tagInteger {
		ret.EngineID = "0x" + hex.EncodeToString(usm[0].value)

		ret.EngineIDFormat,
			ret.EngineIDData,
			ret.EnterpriseID,
			ret.EnterpriseName = formatEngineID(usm[0].value)

		ret.SNMPEngineBoots = decodeInteger(usm[1].value)
		ret.SNMPEngineTime = decodeInteger(usm[2].value)
	}

	scoped, err := readTLVs(children[3].value)
	if err != nil {
		return ret, nil
	}
	if len(scoped) == 3 && scoped[2].tag == tagReport {
		pduChildren, err := readTLVs(scoped[2].value)
		if err != nil {
			return ret, nil
		}
		if len(pduChildren) == 4 {
			ret.ErrorStatus = decodeInteger(pduChildren[1].value)
			ret.ErrorIndex = decodeInteger(pduChildren[2].value)
			varbinds, err := readTLVs(pduChildren[3].value)
			if err == nil && len(varbinds) > 0 {
				pair, err := readTLVs(varbinds[0].value)
				if err == nil && len(pair) == 2 && pair[0].tag == tagObjectID {
					ret.ReportOID, _ = decodeOID(pair[0].value)
					ret.ReportValue = formatValue(pair[1])
					ret.Values[ret.ReportOID] = ret.ReportValue
				}
			}
		}
	}
	return ret, nil
}

func snmpVersionNumber(version string) (int, error) {
	switch strings.ToLower(version) {
	case "1":
		return 0, nil
	case "2c":
		return 1, nil
	default:
		return 0, fmt.Errorf("unsupported SNMP version %q", version)
	}
}

func concat(chunks ...[]byte) []byte {
	var out []byte
	for _, chunk := range chunks {
		out = append(out, chunk...)
	}
	return out
}

func wrap(tag byte, value []byte) []byte {
	return append(append([]byte{tag}, encodeLength(len(value))...), value...)
}

func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n)}, tmp...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(tmp))}, tmp...)
}

func encodeInteger(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n)}, out...)
		n >>= 8
	}
	if out[0]&0x80 != 0 {
		out = append([]byte{0}, out...)
	}
	return out
}

func decodeInteger(b []byte) int {
	var out int
	for _, v := range b {
		out = (out << 8) | int(v)
	}
	return out
}

func encodeOID(s string) ([]byte, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid oid %q", s)
	}
	nums := make([]int, len(parts))
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid oid %q", s)
		}
		nums[i] = n
	}
	if nums[0] > 2 || nums[1] > 39 {
		return nil, fmt.Errorf("invalid oid %q", s)
	}
	out := []byte{byte(nums[0]*40 + nums[1])}
	for _, n := range nums[2:] {
		out = append(out, encodeBase128(n)...)
	}
	return out, nil
}

func encodeBase128(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n & 0x7f)}, out...)
		n >>= 7
	}
	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}
	return out
}

func decodeOID(b []byte) (string, error) {
	if len(b) == 0 {
		return "", errInvalidSNMP
	}
	parts := []int{int(b[0]) / 40, int(b[0]) % 40}
	var value int
	for _, v := range b[1:] {
		value = (value << 7) | int(v&0x7f)
		if v&0x80 == 0 {
			parts = append(parts, value)
			value = 0
		}
	}
	if value != 0 {
		return "", errInvalidSNMP
	}
	strs := make([]string, len(parts))
	for i, part := range parts {
		strs[i] = strconv.Itoa(part)
	}
	return strings.Join(strs, "."), nil
}

func readTLVs(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		item, rest, err := readTLV(b)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
		b = rest
	}
	return out, nil
}

func readTLV(b []byte) (tlv, []byte, error) {
	if len(b) < 2 {
		return tlv{}, nil, errInvalidSNMP
	}
	tag := b[0]
	length, headerLen, err := readLength(b[1:])
	if err != nil {
		return tlv{}, nil, err
	}
	start := 1 + headerLen
	end := start + length
	if end > len(b) {
		return tlv{}, nil, errInvalidSNMP
	}
	return tlv{tag: tag, value: b[start:end]}, b[end:], nil
}

func readLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, errInvalidSNMP
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), 1, nil
	}
	count := int(b[0] & 0x7f)
	if count == 0 || count > 4 || len(b) < 1+count {
		return 0, 0, errInvalidSNMP
	}
	var length int
	for _, v := range b[1 : 1+count] {
		length = (length << 8) | int(v)
	}
	return length, 1 + count, nil
}

func formatValue(v tlv) string {
	switch v.tag {
	case tagOctetString:
		if bytes.IndexFunc(v.value, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\r' && r != '\t' }) == -1 {
			return string(v.value)
		}
		return "0x" + hex.EncodeToString(v.value)
	case tagInteger, tagCounter32, tagGauge32:
		return strconv.Itoa(decodeInteger(v.value))
	case tagObjectID:
		oid, err := decodeOID(v.value)
		if err != nil {
			return "0x" + hex.EncodeToString(v.value)
		}
		return oid
	case tagTimeTicks:
		return strconv.Itoa(decodeInteger(v.value))
	case tagIPAddress:
		if len(v.value) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", v.value[0], v.value[1], v.value[2], v.value[3])
		}
		return "0x" + hex.EncodeToString(v.value)
	case tagNull:
		return "null"
	case tagNoSuchObject:
		return "noSuchObject"
	case tagNoSuchInst:
		return "noSuchInstance"
	case tagEndOfMIBView:
		return "endOfMibView"
	case tagOpaque:
		return "0x" + hex.EncodeToString(v.value)
	default:
		return "0x" + hex.EncodeToString(v.value)
	}
}

func formatEngineID(engineID []byte) (string, string, uint32, string) {
	if len(engineID) == 0 {
		return "", "", 0, ""
	}

	var enterpriseID uint32
	var enterpriseName string

	if len(engineID) >= 4 && (engineID[0]&0x80) != 0 {
		enterpriseID =
			(uint32(engineID[0]&0x7f) << 24) |
				(uint32(engineID[1]) << 16) |
				(uint32(engineID[2]) << 8) |
				uint32(engineID[3])

		enterpriseName = lookupEnterprise(enterpriseID)
	}

	if len(engineID) >= 5 && engineID[0]&0x80 != 0 {
		format := engineID[4]
		data := engineID[5:]

		switch format {
		case 3:
			return "mac",
				formatMAC(data),
				enterpriseID,
				enterpriseName
		case 1:
			return "ipv4",
				formatIPv4(data),
				enterpriseID,
				enterpriseName
		case 2:
			return "ipv6",
				"0x" + hex.EncodeToString(data),
				enterpriseID,
				enterpriseName
		case 4:
			if len(data) == 0 {
				return "text",
					"",
					enterpriseID,
					enterpriseName
			}
			return "text",
				string(data),
				enterpriseID,
				enterpriseName
		case 5:
			return "octets",
				"0x" + hex.EncodeToString(data),
				enterpriseID,
				enterpriseName
		default:
			return fmt.Sprintf("format-%d", format),
				"0x" + hex.EncodeToString(data),
				enterpriseID,
				enterpriseName
		}
	}

	return "raw",
		"0x" + hex.EncodeToString(engineID),
		enterpriseID,
		enterpriseName
}

func looksLikeSNMP(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	if b[0] != tagSequence {
		return false
	}
	_, _, err := readLength(b[1:])
	return err == nil
}

func formatMAC(b []byte) string {
	if len(b) != 6 {
		return "0x" + hex.EncodeToString(b)
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}

func formatIPv4(b []byte) string {
	if len(b) != 4 {
		return "0x" + hex.EncodeToString(b)
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
