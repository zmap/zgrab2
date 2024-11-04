package http

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
)

// BEGIN Taken from handshake_server_test.go -- certs for TLS server
func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func bigFromString(s string) *big.Int {
	ret := new(big.Int)
	ret.SetString(s, 10)
	return ret
}

var testRSACertificate = fromHex("308202b030820219a00302010202090085b0bba48a7fb8ca300d06092a864886f70d01010505003045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c7464301e170d3130303432343039303933385a170d3131303432343039303933385a3045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c746430819f300d06092a864886f70d010101050003818d0030818902818100bb79d6f517b5e5bf4610d0dc69bee62b07435ad0032d8a7a4385b71452e7a5654c2c78b8238cb5b482e5de1f953b7e62a52ca533d6fe125c7a56fcf506bffa587b263fb5cd04d3d0c921964ac7f4549f5abfef427100fe1899077f7e887d7df10439c4a22edb51c97ce3c04c3b326601cfafb11db8719a1ddbdb896baeda2d790203010001a381a73081a4301d0603551d0e04160414b1ade2855acfcb28db69ce2369ded3268e18883930750603551d23046e306c8014b1ade2855acfcb28db69ce2369ded3268e188839a149a4473045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c746482090085b0bba48a7fb8ca300c0603551d13040530030101ff300d06092a864886f70d010105050003818100086c4524c76bb159ab0c52ccf2b014d7879d7a6475b55a9566e4c52b8eae12661feb4f38b36e60d392fdf74108b52513b1187a24fb301dbaed98b917ece7d73159db95d31d78ea50565cd5825a2d5a5f33c4b6d8c97590968c0f5298b5cd981f89205ff2a01ca31b9694dda9fd57e970e8266d71999b266e3850296c90a7bdd9")
var testSNICertificate = fromHex("308201f23082015da003020102020100300b06092a864886f70d01010530283110300e060355040a130741636d6520436f311430120603550403130b736e69746573742e636f6d301e170d3132303431313137343033355a170d3133303431313137343533355a30283110300e060355040a130741636d6520436f311430120603550403130b736e69746573742e636f6d30819d300b06092a864886f70d01010103818d0030818902818100bb79d6f517b5e5bf4610d0dc69bee62b07435ad0032d8a7a4385b71452e7a5654c2c78b8238cb5b482e5de1f953b7e62a52ca533d6fe125c7a56fcf506bffa587b263fb5cd04d3d0c921964ac7f4549f5abfef427100fe1899077f7e887d7df10439c4a22edb51c97ce3c04c3b326601cfafb11db8719a1ddbdb896baeda2d790203010001a3323030300e0603551d0f0101ff0404030200a0300d0603551d0e0406040401020304300f0603551d2304083006800401020304300b06092a864886f70d0101050381810089c6455f1c1f5ef8eb1ab174ee2439059f5c4259bb1a8d86cdb1d056f56a717da40e95ab90f59e8deaf627c157995094db0802266eb34fc6842dea8a4b68d9c1389103ab84fb9e1f85d9b5d23ff2312c8670fbb540148245a4ebafe264d90c8a4cf4f85b0fac12ac2fc4a3154bad52462868af96c62c6525d652b6e31845bdcc")

var testRSAPrivateKey = &rsa.PrivateKey{
	PublicKey: rsa.PublicKey{
		N: bigFromString("131650079503776001033793877885499001334664249354723305978524647182322416328664556247316495448366990052837680518067798333412266673813370895702118944398081598789828837447552603077848001020611640547221687072142537202428102790818451901395596882588063427854225330436740647715202971973145151161964464812406232198521"),
		E: 65537,
	},
	D: bigFromString("29354450337804273969007277378287027274721892607543397931919078829901848876371746653677097639302788129485893852488285045793268732234230875671682624082413996177431586734171663258657462237320300610850244186316880055243099640544518318093544057213190320837094958164973959123058337475052510833916491060913053867729"),
	Primes: []*big.Int{
		bigFromString("11969277782311800166562047708379380720136961987713178380670422671426759650127150688426177829077494755200794297055316163155755835813760102405344560929062149"),
		bigFromString("10998999429884441391899182616418192492905073053684657075974935218461686523870125521822756579792315215543092255516093840728890783887287417039645833477273829"),
	},
}

// END Taken from handshake_server_test.go -- certs for TLS server

// Get the tls.Config object for the server; adapted from handshake_server_test.go.
func getTLSConfig() *tls.Config {
	testConfig := &tls.Config{
		Time:               func() time.Time { return time.Unix(0, 0) },
		Certificates:       make([]tls.Certificate, 2),
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionTLS12,
	}
	testConfig.Certificates[0].Certificate = [][]byte{testRSACertificate}
	testConfig.Certificates[0].PrivateKey = testRSAPrivateKey
	testConfig.Certificates[1].Certificate = [][]byte{testSNICertificate}
	testConfig.Certificates[1].PrivateKey = testRSAPrivateKey
	testConfig.BuildNameToCertificate()
	return testConfig
}

// Helper function to write and check for short writes
func _write(writer io.Writer, data []byte) error {
	n, err := writer.Write(data)
	if err == nil && len(data) != n {
		err = io.ErrShortWrite
	}
	return err
}

// Start a local server that sends responds to any requests with a cfg.headerSize-byte set of
// headers followed by a cfg.bodySize-byte body.
// The response ends up looking like this:
// HTTP/1.0 200 OK
// Bogus-Header: XXX...
// Content-Length: <bodySize>
//
// XXXX....
func (cfg *readLimitTestConfig) runFakeHTTPServer(t *testing.T) {
	endpoint := fmt.Sprintf("127.0.0.1:%d", cfg.port)
	listener, err := net.Listen("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listener.Close()
		sock, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer sock.Close()
		if cfg.tls {
			tlsSock := tls.Server(sock, getTLSConfig())
			if err := tlsSock.Handshake(); err != nil {
				t.Fatalf("server handshake error: %v", err)
			}
			sock = tlsSock
		}
		// don't care what the client sends, always respond with a HTTP-like response
		buf := make([]byte, 1)
		_, err = sock.Read(buf)
		if err != nil {
			// any error, including EOF, is unexpected -- the client should send something
			t.Fatalf("Unexpected error reading from client: %v", err)
		}

		head := "HTTP/1.0 200 OK\r\nBogus-Header: X"
		if cfg.customHeader != nil {
			head = *cfg.customHeader
		}
		headSuffix := fmt.Sprintf("\r\nContent-Length: %d\r\n\r\n", cfg.bodySize)
		if cfg.customSuffix != nil {
			headSuffix = *cfg.customSuffix
		}
		size := cfg.headerSize - len(head) - len(headSuffix)
		if size < 0 {
			t.Fatalf("Header size %d too small: must be at least %d bytes", cfg.headerSize, len(head)+len(headSuffix))
		}
		if err := _write(sock, []byte(head)); err != nil {
			t.Fatalf("write error: %v", err)
		}
		chunkSize := 256
		sent := len(head)
		chunk := []byte(strings.Repeat("X", chunkSize))
		for i := 0; i < size; i += chunkSize {
			if i+chunkSize > size {
				chunk = []byte(strings.Repeat("X", size-i))
			}
			if err := _write(sock, chunk); err != nil {
				t.Logf("Failed writing to client after %d bytes: %v", sent, err)
				return
			}
			sent += len(chunk)
		}

		if err := _write(sock, []byte(headSuffix)); err != nil {
			t.Logf("Failed writing foot to client: %v", err)
			return
		}
		sent += len(headSuffix)
		body := strings.Repeat("X", cfg.bodySize)
		if err := _write(sock, []byte(body)); err != nil {
			t.Logf("Failed writing body to client: %v", err)
			return
		}
	}()
}

// Get an HTTP scanner module with the desired config
func (cfg *readLimitTestConfig) getScanner(t *testing.T) *Scanner {
	var module Module
	flags := module.NewFlags().(*Flags)
	flags.Endpoint = "/"
	flags.Method = "GET"
	flags.UserAgent = "Mozilla/5.0 zgrab/0.x"
	if cfg.maxBodySize&0x03ff != 0 {
		t.Fatalf("%d is not a valid maxBodySize (must be a multiple of 1024)", cfg.maxBodySize)
	}
	flags.MaxSize = cfg.maxBodySize / 1024
	flags.MaxRedirects = 0
	flags.Timeout = 1 * time.Second
	flags.Port = uint(cfg.port)
	flags.UseHTTPS = cfg.tls
	zgrab2.DefaultBytesReadLimit = cfg.maxReadSize
	scanner := module.NewScanner()
	scanner.Init(flags)
	return scanner.(*Scanner)
}

// Configuration for a single test run
type readLimitTestConfig struct {
	// if true, the client/server will use TLS. NOTE: the limits are on the *raw* connection.
	tls bool

	// port where the server listens.
	port int

	// Bodies larger than this are truncated. NOTE: this must be a multiple of 1024, since MaxSize
	// is given in kilobytes.
	maxBodySize int

	// The maximum number of bytes to read from the (raw) socket. Beyond that data is truncated and
	// EOF is returned.
	maxReadSize int

	// The size of the HTTP server's "header" (actually, all of the data before the body). Must be
	// at least 58 (the size of the static parts of the response).
	headerSize int

	// The size of the HTTP body to send (the Content-Length).
	bodySize int

	// The status that should be returned by the scan.
	expectedStatus zgrab2.ScanStatus

	// If set, the error returned by the scan must contain this.
	expectedError string

	// If set, return a custom header
	customHeader *string

	customSuffix *string
}

const (
	readLimitTestConfigHTTPBasePort  = 0x7f7f
	readLimitTestConfigHTTPSBasePort = 0x7bbc
)

func adr(s string) *string { return &s }

var readLimitTestConfigs = map[string]*readLimitTestConfig{
	// The socket truncates the connection while reading the body. To the client it looks as if the
	// server closed the connection prior to sending Content-Length bytes; the result is success,
	// but with a truncated body.
	// bodySize + headerSize > maxReadSize > headerSize
	"truncate_read_body": {
		tls:            false,
		port:           readLimitTestConfigHTTPBasePort,
		maxBodySize:    2048,
		maxReadSize:    1024,
		headerSize:     64,
		bodySize:       4096,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
	// NOTE: There is no tls_truncate_read_body, since the truncation will almost certainly occur
	// in the middle of a TLS packet -- so the response would always be "unexpected EOF"

	// The HTTP library stops reading the body after reaching its internal limit. It returns success
	// and the truncated body.
	// maxReadSize > headerSize + bodySize > bodySize > maxBodySize
	"truncate_body": {
		tls:            false,
		port:           readLimitTestConfigHTTPBasePort + 1,
		maxBodySize:    2048,
		maxReadSize:    8192,
		headerSize:     64,
		bodySize:       4096,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
	"tls_truncate_body": {
		tls:            true,
		port:           readLimitTestConfigHTTPSBasePort + 1,
		maxBodySize:    2048,
		maxReadSize:    8192,
		headerSize:     64,
		bodySize:       4096,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},

	// The socket truncates the connection while reading the headers. The result isn't a completely valid HTTP
	// response, but we capture the output regardless
	// headerSize > maxReadSize
	"truncate_read_header": {
		tls:            false,
		port:           readLimitTestConfigHTTPBasePort + 2,
		maxBodySize:    1024,
		maxReadSize:    2048,
		headerSize:     3072,
		bodySize:       0,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
	"tls_truncate_read_header": {
		tls:            true,
		port:           readLimitTestConfigHTTPSBasePort + 2,
		maxBodySize:    1024,
		maxReadSize:    2048,
		headerSize:     3072,
		bodySize:       0,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},

	// The socket truncates the connection while reading the status code. The result isn't a valid HTTP
	// response
	// headerSize > maxReadSize
	"invalid_status_code": {
		tls:            false,
		port:           readLimitTestConfigHTTPBasePort + 2,
		maxBodySize:    8192,
		maxReadSize:    8192,
		headerSize:     1024,
		bodySize:       1024,
		customHeader:   adr("HTTP/1.0 200"),
		expectedError:  "malformed HTTP status code",
		expectedStatus: zgrab2.SCAN_UNKNOWN_ERROR,
	},
	"tls_invalid_status_code": {
		tls:            true,
		port:           readLimitTestConfigHTTPSBasePort + 2,
		maxBodySize:    8192,
		maxReadSize:    8192,
		headerSize:     1024,
		bodySize:       1024,
		customHeader:   adr("HTTP/1.0 200"),
		expectedError:  "malformed HTTP status code",
		expectedStatus: zgrab2.SCAN_UNKNOWN_ERROR,
	},

	"invalid_no_status": {
		tls:            false,
		port:           readLimitTestConfigHTTPBasePort + 2,
		maxBodySize:    8192,
		maxReadSize:    8192,
		headerSize:     1024,
		bodySize:       1024,
		customHeader:   adr(""),
		customSuffix:   adr(""),
		expectedError:  "malformed HTTP response",
		expectedStatus: zgrab2.SCAN_UNKNOWN_ERROR,
	},

	"invalid_response": {
		tls:            false,
		port:           readLimitTestConfigHTTPBasePort + 2,
		maxBodySize:    8192,
		maxReadSize:    8192,
		headerSize:     1024,
		bodySize:       1024,
		customHeader:   adr(""),
		expectedError:  "malformed HTTP response",
		expectedStatus: zgrab2.SCAN_UNKNOWN_ERROR,
	},

	"invalid_low_read_limit": {
		tls:            false,
		port:           readLimitTestConfigHTTPBasePort + 2,
		maxBodySize:    8192,
		maxReadSize:    1,
		headerSize:     1024,
		bodySize:       1024,
		expectedError:  "malformed HTTP response",
		expectedStatus: zgrab2.SCAN_UNKNOWN_ERROR,
	},

	// Happy case. None of the limits are hit.
	// maxReadSize >= maxBodySize > bodySize + headerSize
	"happy_case": {
		tls:            false,
		port:           readLimitTestConfigHTTPBasePort + 3,
		maxBodySize:    8192,
		maxReadSize:    8192,
		headerSize:     1024,
		bodySize:       1024,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
	"tls_happy_case": {
		tls:            true,
		port:           readLimitTestConfigHTTPSBasePort + 3,
		maxBodySize:    8192,
		maxReadSize:    8192,
		headerSize:     1024,
		bodySize:       1024,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
}

// Try to get the HTTP body from a result; otherwise return the empty string.
func getResponse(result interface{}) *http.Response {
	if result == nil {
		return nil
	}
	httpResult, ok := result.(*Results)
	if !ok {
		return nil
	}
	return httpResult.Response
}

// Run a single test with the given configuration.
func (cfg *readLimitTestConfig) runTest(t *testing.T, testName string) {
	scanner := cfg.getScanner(t)
	cfg.runFakeHTTPServer(t)
	target := zgrab2.ScanTarget{
		IP: net.ParseIP("127.0.0.1"),
	}
	status, ret, err := scanner.Scan(target)
	response := getResponse(ret)

	if status != cfg.expectedStatus {
		t.Errorf("Wrong status: expected %s, got %s with %+v", cfg.expectedStatus, status, response)
	}
	if err != nil {
		if !strings.Contains(err.Error(), cfg.expectedError) {
			t.Errorf("Wrong error: expected %s, got %s", cfg.expectedError, err.Error())
		}
	} else if len(cfg.expectedError) > 0 {
		t.Errorf("Expected error '%s' but got none", cfg.expectedError)
	}
	if cfg.expectedStatus == zgrab2.SCAN_SUCCESS {
		if response == nil {
			t.Errorf("Expected response, but got none")
		}

		statusCode := response.Status
		if statusCode != "200 OK" {
			t.Errorf("Expected status %s, but got %s", "200 OK", statusCode)
		}

		body := response.BodyText
		if body == "" {
			if cfg.bodySize != 0 {
				t.Errorf("Expected success, but got no body")
			}
		} else {
			if len(body) > cfg.maxBodySize || len(body) > cfg.maxReadSize {
				t.Errorf("Body exceeds max size: len(body)=%d; maxBodySize=%d, maxReadSize=%d", len(body), cfg.maxBodySize, cfg.maxReadSize)
			}
			if !cfg.tls {
				if len(body)+cfg.headerSize > cfg.maxReadSize {
					t.Errorf("Body and header exceed max read size: len(body)=%d, headerSize=%d, maxReadSize=%d", len(body), cfg.headerSize, cfg.maxReadSize)
				}
			}
		}
	}
}

// TestReadLimitHTTP checks that the HTTP scanner works as expected with the default
// ReadLimitExeededAction (specifically, ReadLimnitExceededActionTruncate) defined in conn.go.
func TestReadLimitHTTP(t *testing.T) {
	if zgrab2.DefaultReadLimitExceededAction != zgrab2.ReadLimitExceededActionTruncate {
		t.Logf("Warning: DefaultReadLimitExceededAction is %s, not %s", zgrab2.DefaultReadLimitExceededAction, zgrab2.ReadLimitExceededActionTruncate)
	}
	for testName, cfg := range readLimitTestConfigs {
		cfg.runTest(t, testName)
	}
}
