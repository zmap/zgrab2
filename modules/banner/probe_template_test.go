package banner

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeTemplateExpandAllFields(t *testing.T) {
	template, err := parseProbeTemplate([]byte(
		"${SADDR}|${DADDR}|${SPORT}|${DPORT}|" +
			"${SADDR_N}${DADDR_N}${SPORT_N}${DPORT_N}|" +
			"${RAND_BYTE=2}|${RAND_DIGIT=2}|${RAND_ALPHA=2}|${RAND_ALPHANUM=2}|" +
			"${HEX=00ff}|${UNIXTIME_SEC}${UNIXTIME_USEC}${NTP_TIMESTAMP}",
	))
	if err != nil {
		t.Fatalf("parseProbeTemplate() error = %v", err)
	}

	now := time.Unix(1_700_000_000, 500_000_000)
	context := &probeTemplateContext{
		sourceIP:        net.ParseIP("192.0.2.1"),
		destinationIP:   net.ParseIP("198.51.100.2"),
		sourcePort:      12345,
		destinationPort: 443,
		now:             now,
		random:          bytes.NewReader([]byte{0x00, 0xff, 0, 1, 0, 51, 0, 61}),
	}

	got, err := template.expand(context)
	if err != nil {
		t.Fatalf("expand() error = %v", err)
	}

	var want bytes.Buffer
	want.WriteString("192.0.2.1|198.51.100.2|12345|443|")
	want.Write(net.ParseIP("192.0.2.1").To4())
	want.Write(net.ParseIP("198.51.100.2").To4())
	_ = binary.Write(&want, binary.BigEndian, uint16(12345))
	_ = binary.Write(&want, binary.BigEndian, uint16(443))
	want.WriteByte('|')
	want.Write([]byte{0x01, 0x00})
	want.WriteString("|01|aZ|a9|")
	want.Write([]byte{0x00, 0xff})
	want.WriteByte('|')
	_ = binary.Write(&want, binary.BigEndian, uint32(now.Unix()))
	_ = binary.Write(&want, binary.BigEndian, uint32(500_000))
	_ = binary.Write(&want, binary.BigEndian, uint32(now.Unix()+2_208_988_800))
	_ = binary.Write(&want, binary.BigEndian, uint32(1<<31))

	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("expand() = %x, want %x", got, want.Bytes())
	}
}

func TestProbeTemplateLeavesUnknownAndUnclosedFieldsLiteral(t *testing.T) {
	input := []byte("a${UNKNOWN=bad}b${DADDR")
	template, err := parseProbeTemplate(input)
	if err != nil {
		t.Fatalf("parseProbeTemplate() error = %v", err)
	}
	got, err := template.expand(&probeTemplateContext{})
	if err != nil {
		t.Fatalf("expand() error = %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("expand() = %q, want %q", got, input)
	}
}

func TestProbeTemplateValidation(t *testing.T) {
	tests := []string{
		"${HEX}",
		"${HEX=0}",
		"${HEX=zz}",
		"${RAND_BYTE=}",
		"${RAND_DIGIT=-1}",
		"${RAND_ALPHA=nope}",
		"${RAND_ALPHANUM=1473}",
		"${DADDR=bad}",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := parseProbeTemplate([]byte(input)); err == nil {
				t.Fatalf("parseProbeTemplate(%q) error = nil", input)
			}
		})
	}
}

func TestProbeTemplateAcceptsMaximumRandomLength(t *testing.T) {
	template, err := parseProbeTemplate([]byte("${RAND_BYTE=1472}"))
	if err != nil {
		t.Fatalf("parseProbeTemplate() error = %v", err)
	}
	got, err := template.expand(&probeTemplateContext{
		random: strings.NewReader(strings.Repeat("x", maxTemplateFieldLength)),
	})
	if err != nil {
		t.Fatalf("expand() error = %v", err)
	}
	if len(got) != maxTemplateFieldLength {
		t.Fatalf("expand() length = %d, want %d", len(got), maxTemplateFieldLength)
	}
}

func TestProbeTemplateNetworkAddressRequiresIPv4(t *testing.T) {
	template, err := parseProbeTemplate([]byte("${SADDR_N}${DADDR_N}"))
	if err != nil {
		t.Fatalf("parseProbeTemplate() error = %v", err)
	}
	_, err = template.expand(&probeTemplateContext{
		sourceIP:      net.ParseIP("2001:db8::1"),
		destinationIP: net.ParseIP("2001:db8::2"),
	})
	if err == nil || !strings.Contains(err.Error(), "SADDR_N requires an IPv4 connection") {
		t.Fatalf("expand() error = %v, want IPv4 requirement", err)
	}
}

func TestProbeTemplateTextAddressesSupportIPv6(t *testing.T) {
	template, err := parseProbeTemplate([]byte("${SADDR}|${DADDR}"))
	if err != nil {
		t.Fatalf("parseProbeTemplate() error = %v", err)
	}
	got, err := template.expand(&probeTemplateContext{
		sourceIP:      net.ParseIP("2001:db8::1"),
		destinationIP: net.ParseIP("2001:db8::2"),
	})
	if err != nil {
		t.Fatalf("expand() error = %v", err)
	}
	if string(got) != "2001:db8::1|2001:db8::2" {
		t.Fatalf("expand() = %q", got)
	}
}

func TestParseTemplateAddress(t *testing.T) {
	ip, port, err := parseTemplateAddress(&net.TCPAddr{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 1234,
		Zone: "test",
	})
	if err != nil {
		t.Fatalf("parseTemplateAddress() error = %v", err)
	}
	if !ip.Equal(net.ParseIP("2001:db8::1")) || port != 1234 {
		t.Fatalf("parseTemplateAddress() = %s:%d", ip, port)
	}
}
