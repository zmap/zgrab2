package banner

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const maxTemplateFieldLength = 1472

type templateFieldType uint8

const (
	templateLiteral templateFieldType = iota
	templateSourceAddressNetwork
	templateSourceAddress
	templateDestinationAddressNetwork
	templateDestinationAddress
	templateSourcePortNetwork
	templateSourcePort
	templateDestinationPortNetwork
	templateDestinationPort
	templateRandomBytes
	templateRandomDigits
	templateRandomAlpha
	templateRandomAlphanumeric
	templateHex
	templateUnixTimeSeconds
	templateUnixTimeMicroseconds
	templateNTPTimestamp
)

type templateField struct {
	fieldType templateFieldType
	data      []byte
	length    int
}

type probeTemplate struct {
	fields []templateField
}

type probeTemplateContext struct {
	sourceIP        net.IP
	destinationIP   net.IP
	sourcePort      uint16
	destinationPort uint16
	now             time.Time
	random          io.Reader
}

func parseProbeTemplate(probe []byte) (*probeTemplate, error) {
	template := &probeTemplate{}

	for cursor := 0; cursor < len(probe); {
		startOffset := bytes.Index(probe[cursor:], []byte("${"))
		if startOffset < 0 {
			template.addLiteral(probe[cursor:])
			break
		}

		start := cursor + startOffset
		template.addLiteral(probe[cursor:start])

		endOffset := bytes.IndexByte(probe[start+2:], '}')
		if endOffset < 0 {
			template.addLiteral(probe[start:])
			break
		}

		end := start + 2 + endOffset
		field, recognized, err := parseTemplateField(string(probe[start+2 : end]))
		if err != nil {
			return nil, err
		}
		if recognized {
			template.fields = append(template.fields, field)
		} else {
			template.addLiteral(probe[start : end+1])
		}
		cursor = end + 1
	}

	return template, nil
}

func (template *probeTemplate) addLiteral(data []byte) {
	if len(data) == 0 {
		return
	}
	copied := append([]byte(nil), data...)
	if len(template.fields) > 0 && template.fields[len(template.fields)-1].fieldType == templateLiteral {
		template.fields[len(template.fields)-1].data = append(template.fields[len(template.fields)-1].data, copied...)
		return
	}
	template.fields = append(template.fields, templateField{fieldType: templateLiteral, data: copied})
}

func parseTemplateField(spec string) (templateField, bool, error) {
	name, parameter, hasParameter := strings.Cut(spec, "=")
	fieldType, recognized := templateFieldTypes[name]
	if !recognized {
		return templateField{}, false, nil
	}

	field := templateField{fieldType: fieldType}
	switch fieldType {
	case templateHex:
		if !hasParameter || parameter == "" {
			return templateField{}, true, errors.New("template field HEX requires a hex value")
		}
		if len(parameter)%2 != 0 {
			return templateField{}, true, fmt.Errorf("template field HEX has odd-length value %q", parameter)
		}
		decoded, err := hex.DecodeString(parameter)
		if err != nil {
			return templateField{}, true, fmt.Errorf("template field HEX has invalid value %q: %w", parameter, err)
		}
		if len(decoded) > maxTemplateFieldLength {
			return templateField{}, true, fmt.Errorf("template field HEX exceeds maximum length %d", maxTemplateFieldLength)
		}
		field.data = decoded
	case templateRandomBytes, templateRandomDigits, templateRandomAlpha, templateRandomAlphanumeric:
		if !hasParameter {
			field.length = 0
			return field, true, nil
		}
		if parameter == "" {
			return templateField{}, true, fmt.Errorf("template field %s has an empty length", name)
		}
		length, err := strconv.Atoi(parameter)
		if err != nil {
			return templateField{}, true, fmt.Errorf("template field %s has invalid length %q: %w", name, parameter, err)
		}
		if length < 0 || length > maxTemplateFieldLength {
			return templateField{}, true, fmt.Errorf("template field %s length must be between 0 and %d", name, maxTemplateFieldLength)
		}
		field.length = length
	default:
		if hasParameter {
			if parameter == "" {
				return templateField{}, true, fmt.Errorf("template field %s has an empty parameter", name)
			}
			length, err := strconv.Atoi(parameter)
			if err != nil || length < 0 || length > maxTemplateFieldLength {
				return templateField{}, true, fmt.Errorf("template field %s has invalid parameter %q", name, parameter)
			}
		}
	}
	return field, true, nil
}

var templateFieldTypes = map[string]templateFieldType{
	"SADDR_N":       templateSourceAddressNetwork,
	"SADDR":         templateSourceAddress,
	"DADDR_N":       templateDestinationAddressNetwork,
	"DADDR":         templateDestinationAddress,
	"SPORT_N":       templateSourcePortNetwork,
	"SPORT":         templateSourcePort,
	"DPORT_N":       templateDestinationPortNetwork,
	"DPORT":         templateDestinationPort,
	"RAND_BYTE":     templateRandomBytes,
	"RAND_DIGIT":    templateRandomDigits,
	"RAND_ALPHA":    templateRandomAlpha,
	"RAND_ALPHANUM": templateRandomAlphanumeric,
	"HEX":           templateHex,
	"UNIXTIME_SEC":  templateUnixTimeSeconds,
	"UNIXTIME_USEC": templateUnixTimeMicroseconds,
	"NTP_TIMESTAMP": templateNTPTimestamp,
}

func newProbeTemplateContext(conn net.Conn) (*probeTemplateContext, error) {
	sourceIP, sourcePort, err := parseTemplateAddress(conn.LocalAddr())
	if err != nil {
		return nil, fmt.Errorf("parse local address for probe template: %w", err)
	}
	destinationIP, destinationPort, err := parseTemplateAddress(conn.RemoteAddr())
	if err != nil {
		return nil, fmt.Errorf("parse remote address for probe template: %w", err)
	}
	return &probeTemplateContext{
		sourceIP:        sourceIP,
		destinationIP:   destinationIP,
		sourcePort:      sourcePort,
		destinationPort: destinationPort,
		now:             time.Now(),
		random:          rand.Reader,
	}, nil
}

func parseTemplateAddress(address net.Addr) (net.IP, uint16, error) {
	if address == nil {
		return nil, 0, errors.New("address is nil")
	}
	switch typedAddress := address.(type) {
	case *net.TCPAddr:
		if typedAddress.Port < 0 || typedAddress.Port > 65535 {
			return nil, 0, fmt.Errorf("invalid TCP port %d", typedAddress.Port)
		}
		return typedAddress.IP, uint16(typedAddress.Port), nil
	case *net.UDPAddr:
		if typedAddress.Port < 0 || typedAddress.Port > 65535 {
			return nil, 0, fmt.Errorf("invalid UDP port %d", typedAddress.Port)
		}
		return typedAddress.IP, uint16(typedAddress.Port), nil
	}
	host, portString, err := net.SplitHostPort(address.String())
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("address host %q is not an IP address", host)
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port %q: %w", portString, err)
	}
	return ip, uint16(port), nil
}

func (template *probeTemplate) expand(context *probeTemplateContext) ([]byte, error) {
	var output []byte
	for _, field := range template.fields {
		var err error
		output, err = expandTemplateField(output, field, context)
		if err != nil {
			return nil, err
		}
	}
	return output, nil
}

func expandTemplateField(output []byte, field templateField, context *probeTemplateContext) ([]byte, error) {
	switch field.fieldType {
	case templateLiteral, templateHex:
		output = append(output, field.data...)
	case templateSourceAddressNetwork:
		return writeIPv4(output, context.sourceIP, "SADDR_N")
	case templateSourceAddress:
		output = append(output, context.sourceIP.String()...)
	case templateDestinationAddressNetwork:
		return writeIPv4(output, context.destinationIP, "DADDR_N")
	case templateDestinationAddress:
		output = append(output, context.destinationIP.String()...)
	case templateSourcePortNetwork:
		output = binary.BigEndian.AppendUint16(output, context.sourcePort)
	case templateSourcePort:
		output = strconv.AppendUint(output, uint64(context.sourcePort), 10)
	case templateDestinationPortNetwork:
		output = binary.BigEndian.AppendUint16(output, context.destinationPort)
	case templateDestinationPort:
		output = strconv.AppendUint(output, uint64(context.destinationPort), 10)
	case templateRandomBytes:
		value := make([]byte, field.length)
		if _, err := io.ReadFull(context.random, value); err != nil {
			return nil, fmt.Errorf("generate RAND_BYTE value: %w", err)
		}
		for i := range value {
			value[i]++
		}
		output = append(output, value...)
	case templateRandomDigits:
		return writeRandomText(output, context.random, field.length, "0123456789")
	case templateRandomAlpha:
		return writeRandomText(output, context.random, field.length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	case templateRandomAlphanumeric:
		return writeRandomText(output, context.random, field.length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	case templateUnixTimeSeconds:
		output = binary.BigEndian.AppendUint32(output, uint32(context.now.Unix()))
	case templateUnixTimeMicroseconds:
		output = binary.BigEndian.AppendUint32(output, uint32(context.now.Nanosecond()/1000))
	case templateNTPTimestamp:
		const ntpEpochOffset = 2208988800
		output = binary.BigEndian.AppendUint32(output, uint32(context.now.Unix()+ntpEpochOffset))
		fraction := uint32((uint64(context.now.Nanosecond()) << 32) / 1_000_000_000)
		output = binary.BigEndian.AppendUint32(output, fraction)
	default:
		return nil, fmt.Errorf("unsupported probe template field type %d", field.fieldType)
	}
	return output, nil
}

func writeIPv4(output []byte, ip net.IP, fieldName string) ([]byte, error) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("template field %s requires an IPv4 connection, got %s", fieldName, ip)
	}
	return append(output, ipv4...), nil
}

func writeRandomText(output []byte, random io.Reader, length int, alphabet string) ([]byte, error) {
	value := make([]byte, length)
	if _, err := io.ReadFull(random, value); err != nil {
		return nil, fmt.Errorf("generate random template value: %w", err)
	}
	for i := range value {
		value[i] = alphabet[int(value[i])%len(alphabet)]
	}
	return append(output, value...), nil
}
