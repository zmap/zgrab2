package omronfins

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

func (cfg *OmronFinsTestConfig) getScanner(t *testing.T) *Scanner {
	var module Module
	scanner := module.NewScanner()
	flags := module.NewFlags().(*Flags)
	flags.Port = uint(cfg.port)
	flags.TCP = cfg.TCP
	flags.TargetTimeout = 5 * time.Second
	scanner.Init(flags)
	return scanner.(*Scanner)
}

func _write(writer io.Writer, data []byte) error {
	n, err := writer.Write(data)
	if err == nil && len(data) != n {
		err = io.ErrShortWrite
	}
	return err
}

// Configuration for a single test run
type OmronFinsTestConfig struct {
	// port where the server listens.
	port int

	// Is it TCP or UDP version
	TCP bool
	// The bytes the server should return.
	response1 []byte

	// The bytes the server should return.
	response2 []byte

	expectedResult DeviceInfo

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

var OmronsConfigs = map[string]OmronFinsTestConfig{
	"Omron Fins CP1L UDP": {
		TCP:       false,
		response1: hexDecode("c00002006300000300ef050100004350314c2d454d343044522d440000002020202030312e3030000000000030312e3037000000000008000000000000000000000000000000000000010000000000000000000000000000000000010004001417800008000000000000"),

		response2: hexDecode("00"),
		expectedResult: DeviceInfo{
			ResponseCodeVal:   "Normal completion",
			ResponseCode:      0,
			ControllerModel:   "CP1L-EM40DR-D",
			ControllerVersion: "01.00",
			ForSystemUse:      "\b",
			ProgramAreaSize:   20,
			IOMsize:           23,
			NoDMSize:          32768,
			Timer:             8,
			ExpansionDMSize:   0,
			NoOfTransitions:   0,
			MemoryCardType:    0,
			MemoryCardTypeVal: "No memory card",
			MemoryCardSize:    0,
		},
		expectedStatus: zgrab2.SCAN_SUCCESS,
		expectedError:  "",
	},
	"Omron Fins CP1L TCP": {
		TCP:       true,
		response1: hexDecode("46494e53000000100000000100000000000000fb00000021"),
		response2: hexDecode("46494e53000000720000000200000000c0000200fbef00210005050100004350314c2d454d343044522d440000002020202030312e3030000000000030312e3038000000000000000000000000000000000000000000000000010000000000000000000000000000000000010100001417800008000000000000"),

		expectedResult: DeviceInfo{
			ResponseCodeVal:   "Normal completion",
			ResponseCode:      0,
			ControllerModel:   "CP1L-EM40DR-D",
			ControllerVersion: "01.00",
			ForSystemUse:      "",
			ProgramAreaSize:   20,
			IOMsize:           23,
			NoDMSize:          32768,
			Timer:             8,
			ExpansionDMSize:   0,
			NoOfTransitions:   0,
			MemoryCardType:    0,
			MemoryCardTypeVal: "No memory card",
			MemoryCardSize:    0,
		},
		expectedStatus: zgrab2.SCAN_SUCCESS,
		expectedError:  "",
	},
}

func getResult(result any) *DeviceInfo {
	finsResult, _ := result.(*DeviceInfo)

	return finsResult
}

// Start a local server that sends responds after two following packets
func (cfg *OmronFinsTestConfig) runFakeServerTCP(t *testing.T, port uint) net.Listener {
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			sock, err := listener.Accept()
			if err != nil {
				return
			}
			defer sock.Close()

			buf := make([]byte, 1024)
			r1, err := sock.Read(buf)
			if err != nil && err != io.EOF && r1 > 0 {
				// Read will return an EOF when it's done reading
				log.Fatalf("1 Unexpected error reading from client: %v", err)
			}
			// The client should ignore this packet but it will wait for it
			if err = _write(sock, cfg.response1); err != nil {
				log.Printf("Failed writing body to client: %v", err)
				return
			}

			r1, err = sock.Read(buf)
			if err != nil && err != io.EOF && r1 > 0 {
				// Read will return an EOF when it's done reading
				log.Fatalf("1 Unexpected error reading from client: %v", err)
			}

			if err := _write(sock, cfg.response2); err != nil {
				log.Printf("Failed writing body to client: %v", err)
				return
			}
		}

	}()
	return listener
}

// Start a local server that sends responds after two following packets
func (cfg *OmronFinsTestConfig) runFakeServerUDP(t *testing.T, port uint) *net.UDPConn {
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	sock, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1024)
		r1, addr, err := sock.ReadFromUDP(buf)
		if err != nil && err != io.EOF && r1 > 0 {
			// Read will return an EOF when it's done reading
			log.Fatalf("1 Unexpected error reading from client: %v", err)
		}
		w, err := sock.WriteToUDP(cfg.response1, addr)

		if w < len(cfg.response1) {
			log.Printf("Failed writing body to client: write less fromt he response")
		} else if err != nil {
			log.Printf("Failed writing body to client: %v", err)

		}
	}()
	return sock
}

func (cfg *OmronFinsTestConfig) runTest(t *testing.T, testName string) {
	scanner := cfg.getScanner(t)
	port := uint(rand.Intn(10000) + 10000)
	if cfg.TCP {
		server := cfg.runFakeServerTCP(t, port)
		defer server.Close()
	} else {
		server := cfg.runFakeServerUDP(t, port)
		defer server.Close()
	}
	target := zgrab2.ScanTarget{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	}

	dialerGroup, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Errorf("Unexpected error got %s", err.Error())
		return
	}
	status, ret, err := scanner.Scan(context.Background(), dialerGroup, &target)

	if status != cfg.expectedStatus {
		t.Errorf("%s Wrong status: expected %s, got %s", testName, cfg.expectedStatus, status)
		return
	}
	if err != nil {
		if !strings.Contains(err.Error(), cfg.expectedError) {
			t.Errorf("%s Wrong error: expected %s, got %s", testName, err.Error(), cfg.expectedError)
		}
	} else if len(cfg.expectedError) > 0 {
		t.Errorf("Expected error '%s' but got none", cfg.expectedError)
	}
	if cfg.expectedStatus == zgrab2.SCAN_SUCCESS {
		result := getResult(ret)

		if result.ResponseCode != cfg.expectedResult.ResponseCode {
			t.Errorf("Received different scan results, actual ResponseCode %d, expected ResponseCode %d",
				result.ResponseCode,
				cfg.expectedResult.ResponseCode,
			)
		} else if result.ResponseCodeVal != cfg.expectedResult.ResponseCodeVal {
			t.Errorf("Received different scan results, actual ResponseCodeVal %s, expected ResponseCodeVal %s",
				result.ResponseCodeVal,
				cfg.expectedResult.ResponseCodeVal,
			)
		} else if result.ControllerModel != cfg.expectedResult.ControllerModel {
			t.Errorf("Received different scan results, actual ControllerModel %s, expected ControllerModel %s",
				result.ControllerModel,
				cfg.expectedResult.ControllerModel,
			)
		} else if result.ControllerVersion != cfg.expectedResult.ControllerVersion {
			t.Errorf("Received different scan results, actual ControllerVersion %s, expected ControllerVersion %s",
				result.ControllerVersion,
				cfg.expectedResult.ControllerVersion,
			)
		} else if result.ForSystemUse != cfg.expectedResult.ForSystemUse {
			t.Errorf("Received different scan results, actual ForSystemUse %s, expected ForSystemUse %s",
				result.ForSystemUse,
				cfg.expectedResult.ForSystemUse,
			)
		} else if result.ProgramAreaSize != cfg.expectedResult.ProgramAreaSize {
			t.Errorf("Received different scan results, actual ProgramAreaSize %d, expected ProgramAreaSize %d",
				result.ProgramAreaSize,
				cfg.expectedResult.ProgramAreaSize,
			)
		} else if result.IOMsize != cfg.expectedResult.IOMsize {
			t.Errorf("Received different scan results, actual IOMsize %d, expected IOMsize %d",
				result.IOMsize,
				cfg.expectedResult.IOMsize,
			)
		} else if result.NoDMSize != cfg.expectedResult.NoDMSize {
			t.Errorf("Received different scan results, actual NoDMSize %d, expected NoDMSize %d",
				result.NoDMSize,
				cfg.expectedResult.NoDMSize,
			)
		} else if result.Timer != cfg.expectedResult.Timer {
			t.Errorf("Received different scan results, actual Timer %d, expected Timer %d",
				result.Timer,
				cfg.expectedResult.Timer,
			)
		} else if result.ExpansionDMSize != cfg.expectedResult.ExpansionDMSize {
			t.Errorf("Received different scan results, actual ExpansionDMSize %d, expected ExpansionDMSize %d",
				result.ExpansionDMSize,
				cfg.expectedResult.ExpansionDMSize,
			)
		} else if result.NoOfTransitions != cfg.expectedResult.NoOfTransitions {
			t.Errorf("Received different scan results, actual NoOfTransitions %d, expected NoOfTransitions %d",
				result.NoOfTransitions,
				cfg.expectedResult.NoOfTransitions,
			)
		} else if result.MemoryCardType != cfg.expectedResult.MemoryCardType {
			t.Errorf("Received different scan results, actual MemoryCardType %d, expected MemoryCardType %d",
				result.MemoryCardType,
				cfg.expectedResult.MemoryCardType,
			)
		} else if result.MemoryCardTypeVal != cfg.expectedResult.MemoryCardTypeVal {
			t.Errorf("Received different scan results, actual MemoryCardTypeVal %s, expected MemoryCardTypeVal %s",
				result.MemoryCardTypeVal,
				cfg.expectedResult.MemoryCardTypeVal,
			)
		} else if result.MemoryCardSize != cfg.expectedResult.MemoryCardSize {
			t.Errorf("Received different scan results, actual MemoryCardSize %d, expected MemoryCardSize %d",
				result.MemoryCardSize,
				cfg.expectedResult.MemoryCardSize,
			)
		}
	}
}

func TestOmronFis(t *testing.T) {
	for testName, cfg := range OmronsConfigs {
		cfg.runTest(t, testName)
	}
}
