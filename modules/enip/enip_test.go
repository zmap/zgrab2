package enip

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

// Helper function to write and check for short writes
func _write(writer io.Writer, data []byte) error {
	n, err := writer.Write(data)
	if err == nil && len(data) != n {
		err = io.ErrShortWrite
	}
	return err
}

func (cfg *EnipTestConfig) getScanner(t *testing.T) *Scanner {
	var module Module
	scanner := module.NewScanner()
	flags := module.NewFlags().(*Flags)
	flags.Port = uint(cfg.port)
	flags.TargetTimeout = 1 * time.Second
	scanner.Init(flags)
	return scanner.(*Scanner)
}

// Configuration for a single test run
type EnipTestConfig struct {
	// port where the server listens.
	port int

	// The bytes the server should return.
	response []byte

	expectedResult EnipDeviceInfo

	// The status that should be returned by the scan.
	expectedStatus zgrab2.ScanStatus

	// If set, the error returned by the scan must contain this.
	expectedError string
}

func hexDecode(s string) []byte {
	decodeString, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}

	return decodeString
}

var EnipConfigs = map[string]EnipTestConfig{
	"Rockwell": {
		port:     44818,
		response: hexDecode("63003700000000000000000000000000000000000000000001000c00310001000002af12dfc8d20700000000000000002f000c000e0003033400b904b0010f434a31572d454950323128434a322903"),
		expectedResult: EnipDeviceInfo{
			VendorID:     0x2f,
			Vendor:       "Omron Corporation",
			DeviceTypeID: 12,
			DeviceType:   "Communications Adapter",
			ProductCode:  14,
			Revision:     "3.03",
			Serial:       "0x01b004b9",
			ProductName:  "CJ1W-EIP21(CJ2)",
		},
		expectedStatus: zgrab2.SCAN_SUCCESS,
		expectedError:  "",
	},
}

func getResult(result any) EnipDeviceInfo {
	enipResult, _ := result.(EnipDeviceInfo)

	return enipResult
}

// Start a local server that sends responds after two following packets
func (cfg *EnipTestConfig) runFakeEnipServer(t *testing.T) net.Listener {
	endpoint := fmt.Sprintf("127.0.0.1:%d", cfg.port)
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		sock, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		defer sock.Close()

		buf := make([]byte, 1024)
		r1, err := sock.Read(buf)
		if err != nil && err != io.EOF && r1 > 0 {
			// Read will return an EOF when it's done reading
			log.Fatalf("1 Unexpected error reading from client: %v", err)
		}
		// The client should ignore this packet but it will wait for it
		if err := _write(sock, cfg.response); err != nil {
			log.Printf("Failed writing body to client: %v", err)
			return
		}

	}()
	return listener
}

func (cfg *EnipTestConfig) runTest(t *testing.T, testName string) {
	scanner := cfg.getScanner(t)
	server := cfg.runFakeEnipServer(t)
	target := zgrab2.ScanTarget{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 44818,
	}
	dialerGroup, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Errorf("Unexpected error got %s", err.Error())
		return
	}

	status, ret, err := scanner.Scan(context.Background(), dialerGroup, &target)

	if status != cfg.expectedStatus {
		t.Errorf("Wrong status: expected %s, got %s", cfg.expectedStatus, status)
		return
	}
	if err != nil {
		if !strings.Contains(err.Error(), cfg.expectedError) {
			t.Errorf("Wrong error: expected %s, got %s", err.Error(), cfg.expectedError)
		}
	} else if len(cfg.expectedError) > 0 {
		t.Errorf("Expected error '%s' but got none", cfg.expectedError)
	}
	if cfg.expectedStatus == zgrab2.SCAN_SUCCESS {
		result := getResult(ret)

		if result.Vendor != cfg.expectedResult.Vendor {
			t.Errorf("Received different scan results, actual Vendor %s, expected Vendor %s",
				result.Vendor,
				cfg.expectedResult.Vendor,
			)
		} else if result.ProductName != cfg.expectedResult.ProductName {
			t.Errorf("Received different scan results, actual ProductName %s, expected ProductName %s",
				result.ProductName,
				cfg.expectedResult.ProductName,
			)
		} else if result.DeviceType != cfg.expectedResult.DeviceType {
			t.Errorf("Received different scan results, actual DeviceType %s, expected DeviceType %s",
				result.DeviceType,
				cfg.expectedResult.DeviceType,
			)
		} else if result.DeviceTypeID != cfg.expectedResult.DeviceTypeID {
			t.Errorf("Received different scan results, actual DeviceTypeID %d, expected DeviceTypeID %d",
				result.DeviceTypeID,
				cfg.expectedResult.DeviceTypeID,
			)
		} else if result.Revision != cfg.expectedResult.Revision {
			t.Errorf("Received different scan results, actual Revision %s, expected Revision %s",
				result.Revision,
				cfg.expectedResult.Revision,
			)
		} else if result.ProductCode != cfg.expectedResult.ProductCode {
			t.Errorf("Received different scan results, actual ProductCode %d, expected ProductCode %d",
				result.ProductCode,
				cfg.expectedResult.ProductCode,
			)
		} else if result.Serial != cfg.expectedResult.Serial {
			t.Errorf("Received different scan results, actual Serial %s, expected Serial %s",
				result.Serial,
				cfg.expectedResult.Serial,
			)
		} else if result.VendorID != cfg.expectedResult.VendorID {
			t.Errorf("Received different scan results, actual VendorID %d, VendorID Serial %d",
				result.VendorID,
				cfg.expectedResult.VendorID,
			)
		}
		server.Close()
	}
}

func TestEnip(t *testing.T) {
	for testName, cfg := range EnipConfigs {
		cfg.runTest(t, testName)
	}
}
