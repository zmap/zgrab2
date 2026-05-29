package zgrab2

import (
	"net"
	"testing"
)

var (
	testIPv4a      = net.ParseIP("192.168.1.1")
	testIPv4b      = net.ParseIP("192.168.1.2")
	testIPv6a      = net.ParseIP("2001:db8::1")
	testIPv6b      = net.ParseIP("2001:db8::2")
	testTargetIPv4 = net.ParseIP("192.168.1.100")
	testTargetIPv6 = net.ParseIP("2001:db8::100")
)

func TestFilterLocalAddrsByFamily_IPv4Target(t *testing.T) {
	result := filterLocalAddrsByFamily([]net.IP{testIPv4a, testIPv6a, testIPv4b, testIPv6b}, testTargetIPv4)
	if len(result) != 2 {
		t.Fatalf("expected 2 IPv4 addresses, got %d: %v", len(result), result)
	}
	for _, ip := range result {
		if ip.To4() == nil {
			t.Errorf("expected only IPv4 addresses, got %s", ip)
		}
	}
}

func TestFilterLocalAddrsByFamily_IPv6Target(t *testing.T) {
	result := filterLocalAddrsByFamily([]net.IP{testIPv4a, testIPv6a, testIPv6b}, testTargetIPv6)
	if len(result) != 2 {
		t.Fatalf("expected 2 IPv6 addresses, got %d: %v", len(result), result)
	}
	for _, ip := range result {
		if ip.To4() != nil {
			t.Errorf("expected only IPv6 addresses, got %s", ip)
		}
	}
}

func TestFilterLocalAddrsByFamily_NilTarget(t *testing.T) {
	result := filterLocalAddrsByFamily([]net.IP{testIPv4a, testIPv6a}, nil)
	if len(result) != 2 {
		t.Fatalf("expected all addresses returned when target is nil, got %d", len(result))
	}
}

func TestFilterLocalAddrsByFamily_NoMatchFallsBack(t *testing.T) {
	result := filterLocalAddrsByFamily([]net.IP{testIPv6a, testIPv6b}, testTargetIPv4)
	if len(result) != 0 {
		t.Fatalf("expected empty list, got %d: %v", len(result), result)
	}
}

func TestFilterLocalAddrsByFamily_EmptyInput(t *testing.T) {
	result := filterLocalAddrsByFamily(nil, testTargetIPv4)
	if len(result) != 0 {
		t.Fatalf("expected empty result for nil input, got %d", len(result))
	}

	result = filterLocalAddrsByFamily([]net.IP{}, testTargetIPv4)
	if len(result) != 0 {
		t.Fatalf("expected empty result for empty input, got %d", len(result))
	}
}

func TestFilterLocalAddrsByFamily_AllSameFamily(t *testing.T) {
	result := filterLocalAddrsByFamily([]net.IP{testIPv4a, testIPv4b}, testTargetIPv4)
	if len(result) != 2 {
		t.Fatalf("expected 2 addresses when all match, got %d", len(result))
	}
}
