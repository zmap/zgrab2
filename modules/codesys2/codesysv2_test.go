package codesys2

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

func (cfg *CodeSysV2TestConfig) getScanner(t *testing.T) *Scanner {
	var module Module
	scanner := module.NewScanner()
	flags := module.NewFlags().(*Flags)
	flags.Port = uint(cfg.port)
	flags.TargetTimeout = 2 * time.Second
	scanner.Init(flags)
	return scanner.(*Scanner)
}

// Configuration for a single test run
type CodeSysV2TestConfig struct {
	// port where the server listens.
	port int

	// number of loop the fake server need to serve the scanner
	numberOfLoop int
	// The bytes the server should return.
	response []byte

	expectedResult CodeSysV2DeviceInfo

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

var CodeSysV2Configs = map[string]CodeSysV2TestConfig{
	"Virtual": {
		port:         1200,
		numberOfLoop: 1,
		response: hexDecode("bbbbce000000e8030100000000000000b00d0000000002007e13000000000200f401000000000000fa" +
			"000000000000000000000000000000c80600000100010057696e646f77730000000000000000000000000000000000000000000000" +
			"00004e542f323030302f5850205b72756e74696d6520706f72742076332028322e0033532d536d61727420536f66747761726520536f" +
			"6c7574696f6e730000000000f4ff000000000000010000000000ffff000000000000c80000000300000100100000001000000010000000002000003030000100"),
		expectedResult: CodeSysV2DeviceInfo{
			OsType:    "Windows",
			Vendor:    "3S-Smart Software Solutions",
			OsVersion: "NT/2000/XP [runtime port v3 (2.",
		},
		expectedStatus: zgrab2.SCAN_SUCCESS,
		expectedError:  "",
	},
	"ABB": {
		port:         1200,
		numberOfLoop: 2,
		response: hexDecode("bbbb000000ce03e8000000010000000000020cb0000013880000137e00001388000001f400000800000000fa" +
			"000000000000000000000000000006d400030001534d580000000000000000000000000000000000000000000000000000000000736d7" +
			"850504320332e352e32000000000000000000" +
			"0000000000000000000000414242000000000000000000000000000000000000000000000000000000000000000400000000000008000000" +
			"000000139400000000000000c80003000100008000000080000001000000040000000240000000"),
		expectedResult: CodeSysV2DeviceInfo{
			OsType:    "SMX",
			Vendor:    "ABB",
			OsVersion: "smxPPC 3.5.2",
		},
		expectedStatus: zgrab2.SCAN_SUCCESS,
		expectedError:  "",
	},
}

func getResult(result any) CodeSysV2DeviceInfo {
	codesysV2Result, _ := result.(CodeSysV2DeviceInfo)

	return codesysV2Result
}

// Start a local server that sends responds after two following packets
func (cfg *CodeSysV2TestConfig) runFakeCodeSysV2Server(t *testing.T, numberofLoop int) net.Listener {
	endpoint := fmt.Sprintf("127.0.0.1:%d", cfg.port)
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for i := 0; i < numberofLoop; i++ {
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
		}

	}()
	return listener
}

func (cfg *CodeSysV2TestConfig) runTest(t *testing.T, testName string) {
	scanner := cfg.getScanner(t)
	server := cfg.runFakeCodeSysV2Server(t, cfg.numberOfLoop)
	target := zgrab2.ScanTarget{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 1200,
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
		if result.OsVersion != cfg.expectedResult.OsVersion {
			t.Errorf("Received different scan results, actual OsVersion %s, expected OsVersion %s",
				result.OsVersion,
				cfg.expectedResult.OsVersion,
			)
		} else if result.Vendor != cfg.expectedResult.Vendor {
			t.Errorf("Received different scan results, actual Vendor %s, expected Vendor %s",
				result.Vendor,
				cfg.expectedResult.Vendor,
			)
		} else if result.OsType != cfg.expectedResult.OsType {
			t.Errorf("Received different scan results, actual OsType %s, expected OsType %s",
				result.OsType,
				cfg.expectedResult.OsType,
			)
		}
		server.Close()
	}
}

func TestCodeSysV2(t *testing.T) {
	for testName, cfg := range CodeSysV2Configs {
		cfg.runTest(t, testName)
	}
}
