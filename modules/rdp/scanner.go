// Package rdp provides a zgrab2 module that scans for Remote Desktop Protocol.
// Default port: TCP 3389
package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config            *Flags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("rdp", "rdp", module.Description(), 102, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Probe for Remote Desktop Protocol"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(_ []string) error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      true,
		TLSFlags:                        &f.TLSFlags,
	}
	return nil
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "rdp"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// GetScanMetadata returns any metadata on the scan itself from this module.
func (scanner *Scanner) GetScanMetadata() any {
	return nil
}

// Scan probes for rdp services.
// 1. Connect to TCP port
// 2. Send a NTLM negotiate packet
// 7. Return the output
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	scanStatus, result, err := GetBanner(conn)
	if result != nil {
		if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok {
			result.TLSLog = tlsConn.GetLog()
		}
	}
	return scanStatus, result, err
}

func GetBanner(connection net.Conn) (zgrab2.ScanStatus, *RDPResult, error) {

	result := new(RDPResult)

	_, err := connection.Write(NTLM_NEGOTIATE_BLOB)
	responseBytes, readErr := zgrab2.ReadAvailable(connection)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if readErr != nil {
		return zgrab2.TryGetScanStatus(readErr), nil, readErr
	}

	prefixOffset := bytes.Index(responseBytes, NTLM_PREFIX)
	if prefixOffset == -1 {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("not a valid NTLMSSP response")
	}

	if len(responseBytes) < prefixOffset+NTLM_RESPONSE_LENGTH {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("invalid response length %d", len(responseBytes))
	}

	var responseData NTLMSecurityBlob
	responseBytes = responseBytes[prefixOffset:]
	responseBuf := bytes.NewBuffer(responseBytes)

	err = binary.Read(responseBuf, binary.LittleEndian, &responseData)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// 0x2 is the response message type to our request. If we don't have it, we don't know how to handle
	if responseData.MessageType != 0x2 {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("unexpected message type %d", responseData.MessageType)
	}

	if responseData.Reserved != 0 {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("reserved value is not zero %d", responseData.Reserved)
	}

	if !reflect.DeepEqual(responseData.Version[4:], []byte{0, 0, 0, 0xF}) {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("unknown OS info structure in NTLM handshake")
	}

	var versionData OSVersion
	versionBuf := bytes.NewBuffer(responseData.Version[:4])
	err = binary.Read(versionBuf, binary.LittleEndian, &versionData)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("unable to parse version data")
	}
	result.OSVersion = fmt.Sprintf("%d.%d.%d",
		versionData.MajorVersion,
		versionData.MinorVersion,
		versionData.BuildNumber)

	// Parse: DomainName
	targetNameLen := int(responseData.DomainNameLen)
	if targetNameLen > 0 {
		startIndex := int(responseData.DomainNameBufferOffset)
		endIndex := startIndex + targetNameLen
		targetName := strings.ReplaceAll(string(responseBytes[startIndex:endIndex]), "\x00", "")
		result.TargetName = targetName
	}

	targetInfoLen := int(responseData.TargetInfoLen)
	if targetInfoLen > 0 {
		startIndex := int(responseData.TargetInfoBufferOffset)
		if startIndex+targetInfoLen > len(responseBytes) {
			return zgrab2.SCAN_PROTOCOL_ERROR, result, errors.New("invalid TargetInfoLen value")
		}

		var avItem *AVItem
		currentIndex := startIndex

		avItem, err = readAvItem(responseBytes, startIndex, currentIndex, targetInfoLen)
		if err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, result, err
		}

		for avItem.Id != AV_EOL {
			avLength := AV_ITEM_LENGTH + int(avItem.Length)
			if field, exists := NTLM_AV_ID_VALUES[avItem.Id]; exists {
				avValue := string(responseBytes[currentIndex+AV_ITEM_LENGTH : currentIndex+avLength])
				value := strings.ReplaceAll(avValue, "\x00", "")
				switch field {
				case "netbios_computer_name":
					result.NetBIOSComputerName = value
				case "netbios_domain_name":
					result.NetBIOSDomainName = value
				case "fqdn":
					result.DNSComputerName = value
				case "dns_domain_name":
					result.DNSDomainName = value
				case "dns_forest_name":
					result.ForestName = value
				}
			}
			currentIndex += avLength
			avItem, err = readAvItem(responseBytes, startIndex, currentIndex, targetInfoLen)
			if err != nil {
				return zgrab2.SCAN_PROTOCOL_ERROR, result, err
			}
		}
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}

func readAvItem(responseBytes []byte, startIndex int, currentIndex int, targetInfoLen int) (*AVItem, error) {
	var avItem AVItem
	nextIndex := currentIndex + AV_ITEM_LENGTH
	if nextIndex > startIndex+targetInfoLen {
		return nil, errors.New("invalid AV Item list")
	}
	if nextIndex > len(responseBytes) {
		return nil, errors.New("invalid AV Item list")
	}
	avItemBuf := bytes.NewBuffer(responseBytes[currentIndex:nextIndex])
	err := binary.Read(avItemBuf, binary.LittleEndian, &avItem)
	if err != nil {
		return nil, err
	}
	return &avItem, nil
}
