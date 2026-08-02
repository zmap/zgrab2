package codesysv3

import (
	"encoding/binary"
	"net"
	"testing"
)

func utf16leEncode(s string) []byte {
	buf := make([]byte, 0, len(s)*2)
	for _, r := range s {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(r))
		buf = append(buf, b...)
	}
	return buf
}

// buildFakeIdentificationResponse hand-builds a NameService Identification
// datagram (without TCP block-driver framing) matching the layout decoded by
// ParseResponse, so the decoder can be exercised without a live device.
func buildFakeIdentificationResponse() []byte {
	// 8-byte fixed NameService header: magic, hopinfo (header_length=4 words
	// in the low 3 bits), packetinfo (unused by the parser), service_id,
	// message_id, address_lengths=0 (no address words), broadcast_id.
	buf := []byte{nsMagic, 0x04, 0x00, nsResponse, 0x00, 0x00, 0x00, 0x00}

	// 8-byte package header: package_type, version, request_id (all LE).
	pkgHdr := make([]byte, 8)
	binary.LittleEndian.PutUint16(pkgHdr[0:2], pkgIdentification)
	binary.LittleEndian.PutUint16(pkgHdr[2:4], nodeInfoVersion)
	binary.LittleEndian.PutUint32(pkgHdr[4:8], 0xDEADBEEF)
	buf = append(buf, pkgHdr...)

	nodeName := utf16leEncode("Node1")
	deviceName := utf16leEncode("MyPLC")
	vendorName := utf16leEncode("Acme Automation")
	serial := []byte("SN12345")

	// 28-byte fixed body: max_channels, intel_byte_order, addr_difference,
	// parent_addr_size, {node,device,vendor}_name_len, target_type/id/version, flags.
	body := make([]byte, 28)
	binary.LittleEndian.PutUint16(body[0:2], 8) // max_channels
	body[2] = 1                                 // intel_byte_order
	body[3] = 0                                 // addr_difference (unused by parser)
	binary.LittleEndian.PutUint16(body[4:6], 0)
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(nodeName)/2))
	binary.LittleEndian.PutUint16(body[8:10], uint16(len(deviceName)/2))
	binary.LittleEndian.PutUint16(body[10:12], uint16(len(vendorName)/2))
	binary.LittleEndian.PutUint32(body[12:16], 0x1000)     // target_type
	binary.LittleEndian.PutUint32(body[16:20], 0x2000)     // target_id
	binary.LittleEndian.PutUint32(body[20:24], 0x04030201) // target_version -> "4.3.2.1"
	binary.LittleEndian.PutUint32(body[24:28], 0x00000001) // flags
	buf = append(buf, body...)

	buf = append(buf, byte(len(serial)), 0x00, 0x05) // serial_len, oem_len=0, blk_drv_type=5
	buf = append(buf, make([]byte, 9)...)            // 1 pad byte + 8 reserved bytes

	// Variable string table: parent_addr (0 bytes) then NUL-terminated
	// node/device/vendor UTF-16LE names, then the NUL-terminated serial.
	buf = append(buf, nodeName...)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, deviceName...)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, vendorName...)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, serial...)
	buf = append(buf, 0x00)
	return buf
}

func TestParseResponse(t *testing.T) {
	info, err := ParseResponse(buildFakeIdentificationResponse())
	if err != nil {
		t.Fatalf("ParseResponse failed: %v", err)
	}
	if info.VendorName != "Acme Automation" {
		t.Errorf("VendorName = %q, want %q", info.VendorName, "Acme Automation")
	}
	if info.DeviceName != "MyPLC" {
		t.Errorf("DeviceName = %q, want %q", info.DeviceName, "MyPLC")
	}
	if info.NodeName != "Node1" {
		t.Errorf("NodeName = %q, want %q", info.NodeName, "Node1")
	}
	if info.SerialNumber != "SN12345" {
		t.Errorf("SerialNumber = %q, want %q", info.SerialNumber, "SN12345")
	}
	if info.TargetVersionStr != "4.3.2.1" {
		t.Errorf("TargetVersionStr = %q, want %q", info.TargetVersionStr, "4.3.2.1")
	}
	if info.TargetType != 0x1000 || info.TargetID != 0x2000 {
		t.Errorf("TargetType/TargetID = %#x/%#x, want 0x1000/0x2000", info.TargetType, info.TargetID)
	}
	if !info.IntelByteOrder {
		t.Errorf("IntelByteOrder = false, want true")
	}
	if info.BlkDrvType != 5 {
		t.Errorf("BlkDrvType = %d, want 5", info.BlkDrvType)
	}
	if info.RequestID != 0xDEADBEEF {
		t.Errorf("RequestID = %#x, want 0xdeadbeef", info.RequestID)
	}
}

func TestParseResponseTCPFramed(t *testing.T) {
	resp := buildFakeIdentificationResponse()
	framed := make([]byte, 8, 8+len(resp))
	binary.LittleEndian.PutUint32(framed[0:4], tcpBDMagic)
	binary.LittleEndian.PutUint32(framed[4:8], uint32(8+len(resp)))
	framed = append(framed, resp...)

	info, err := ParseResponse(framed)
	if err != nil {
		t.Fatalf("ParseResponse (TCP-framed) failed: %v", err)
	}
	if info.VendorName != "Acme Automation" {
		t.Errorf("VendorName = %q, want %q", info.VendorName, "Acme Automation")
	}
}

func TestParseResponseRejectsGarbage(t *testing.T) {
	if _, err := ParseResponse([]byte("not codesys")); err == nil {
		t.Error("expected error for garbage input, got nil")
	}
	if _, err := ParseResponse(nil); err == nil {
		t.Error("expected error for empty input, got nil")
	}
}

func TestBuildRequests(t *testing.T) {
	local := net.ParseIP("192.168.1.10")
	remote := net.ParseIP("192.168.1.20")

	tcpReq, err := BuildTCPResolveRequest(local, 11740, remote, 11740, 0x1234, 0x11223344)
	if err != nil {
		t.Fatalf("BuildTCPResolveRequest failed: %v", err)
	}
	if len(tcpReq) == 0 {
		t.Error("BuildTCPResolveRequest returned an empty request")
	}
	if binary.LittleEndian.Uint32(tcpReq[:4]) != tcpBDMagic {
		t.Error("BuildTCPResolveRequest did not prepend the CmpBlkDrvTcp magic")
	}

	udpReq, err := BuildUDPResolveRequest(local, 0, 24, 0x1234, 0x11223344)
	if err != nil {
		t.Fatalf("BuildUDPResolveRequest failed: %v", err)
	}
	if len(udpReq) == 0 {
		t.Error("BuildUDPResolveRequest returned an empty request")
	}
	if udpReq[0] != nsMagic {
		t.Error("BuildUDPResolveRequest did not start with the NameService magic")
	}

	if _, err := BuildTCPResolveRequest(net.ParseIP("::1"), 1, remote, 1, 0, 0); err == nil {
		t.Error("expected BuildTCPResolveRequest to reject an IPv6 address")
	}
}
