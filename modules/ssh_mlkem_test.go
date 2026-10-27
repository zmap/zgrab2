package modules

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	upstream "golang.org/x/crypto/ssh"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/ssh"
)

func TestSSHMLKEM(t *testing.T) {
	const hybridKex = "mlkem768x25519-sha256"
	const classicalKex = "curve25519-sha256"
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := upstream.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		clientKex  string
		serverKex  []string
		verbose    bool
		extensions bool
		userauth   bool
		wantKex    string
	}{
		{name: "default-pq-only", serverKex: []string{hybridKex}, wantKex: hybridKex},
		{name: "explicit-pq", clientKex: hybridKex, serverKex: []string{hybridKex}, wantKex: hybridKex},
		{name: "verbose", serverKex: []string{hybridKex}, verbose: true, wantKex: hybridKex},
		{name: "extensions", serverKex: []string{hybridKex}, extensions: true, wantKex: hybridKex},
		{name: "userauth", serverKex: []string{hybridKex}, extensions: true, userauth: true, wantKex: hybridKex},
		{name: "classical-preferred", serverKex: []string{hybridKex, classicalKex}, wantKex: classicalKex},
		{name: "classical-only", serverKex: []string{classicalKex}, wantKex: classicalKex},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				socket, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer socket.Close()
				if err := socket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					serverDone <- err
					return
				}
				config := &upstream.ServerConfig{
					Config:        upstream.Config{KeyExchanges: tt.serverKex},
					ServerVersion: testServerBanner,
					PasswordCallback: func(upstream.ConnMetadata, []byte) (*upstream.Permissions, error) {
						return nil, errors.New("authentication disabled")
					},
				}
				config.AddHostKey(signer)
				conn, _, _, err := upstream.NewServerConn(socket, config)
				if err == nil {
					conn.Close()
					serverDone <- errors.New("scanner unexpectedly authenticated")
					return
				}
				// The scanner deliberately disconnects before authentication.
				if errors.Is(err, io.EOF) {
					serverDone <- nil
					return
				}
				var authErr *upstream.ServerAuthError
				if tt.extensions && errors.As(err, &authErr) {
					wantErrors := 0
					if tt.userauth {
						wantErrors = 1
					}
					if len(authErr.Errors) == wantErrors && (wantErrors == 0 || errors.Is(authErr.Errors[0], upstream.ErrNoAuth)) {
						serverDone <- nil
						return
					}
				}
				serverDone <- err
			}()

			flags := &SSHFlags{
				BaseFlags:         zgrab2.BaseFlags{ConnectTimeout: 5 * time.Second, Verbose: tt.verbose},
				ClientID:          "SSH-2.0-Go",
				KexAlgorithms:     tt.clientKex,
				CollectExtensions: tt.extensions,
				CollectUserAuth:   tt.userauth,
			}
			scanner := new(SSHScanner)
			if err := scanner.Init(flags); err != nil {
				t.Fatal(err)
			}
			dialGroup := &zgrab2.DialerGroup{
				TransportAgnosticDialer: func(ctx context.Context, _ *zgrab2.ScanTarget) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "tcp", listener.Addr().String())
				},
			}
			target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 22}
			status, result, err := scanner.Scan(context.Background(), dialGroup, target)
			if err != nil || status != zgrab2.SCAN_SUCCESS {
				t.Fatalf("Scan = %s, %v", status, err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			log, ok := result.(*ssh.HandshakeLog)
			if !ok || log == nil {
				t.Fatalf("result = %T, want *ssh.HandshakeLog", result)
			}
			if log.ServerID == nil || log.ServerID.Raw != testServerBanner || log.ServerKex == nil || log.AlgorithmSelection == nil {
				t.Fatal("missing server identification or negotiation log")
			}
			if tt.extensions && len(log.Extensions["server-sig-algs"]) == 0 {
				t.Error("missing server-sig-algs extension")
			}
			if tt.userauth && !slices.Contains(log.UserAuth, "password") {
				t.Errorf("userauth = %v, want password", log.UserAuth)
			}

			data, err := json.Marshal(log)
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				AlgorithmSelection struct {
					Kex string `json:"dh_kex_algorithm"`
				} `json:"algorithm_selection"`
				KeyExchange struct {
					Parameters *struct {
						ClientPublic []byte `json:"client_public"`
						ServerPublic []byte `json:"server_public"`
					} `json:"mlkem768x25519_sha256_params"`
					ServerHostKey struct {
						Raw         []byte `json:"raw"`
						Fingerprint string `json:"fingerprint_sha256"`
					} `json:"server_host_key"`
					ServerSignature struct {
						Raw []byte `json:"raw"`
						H   []byte `json:"h"`
					} `json:"server_signature"`
				} `json:"key_exchange"`
			}
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.AlgorithmSelection.Kex != tt.wantKex {
				t.Errorf("negotiated %q, want %q", decoded.AlgorithmSelection.Kex, tt.wantKex)
			}
			kex := decoded.KeyExchange
			if !bytes.Equal(kex.ServerHostKey.Raw, signer.PublicKey().Marshal()) || kex.ServerHostKey.Fingerprint == "" {
				t.Error("missing or incorrect server host key log")
			}
			if len(kex.ServerSignature.Raw) == 0 || len(kex.ServerSignature.H) != 32 {
				t.Error("missing server signature or exchange hash")
			}
			if tt.wantKex == hybridKex {
				if kex.Parameters == nil {
					t.Fatal("missing hybrid exchange parameters")
				}
				if len(kex.Parameters.ServerPublic) != mlkem.CiphertextSize768+32 {
					t.Errorf("server public length = %d", len(kex.Parameters.ServerPublic))
				}
				wantClientLen := 0
				if tt.verbose {
					wantClientLen = mlkem.EncapsulationKeySize768 + 32
				}
				if len(kex.Parameters.ClientPublic) != wantClientLen {
					t.Errorf("client public length = %d, want %d", len(kex.Parameters.ClientPublic), wantClientLen)
				}
			} else if kex.Parameters != nil {
				t.Error("classical exchange unexpectedly logged hybrid parameters")
			}
		})
	}
}

func TestSSHMLKEMConfiguration(t *testing.T) {
	config := new(ssh.ClientConfig)
	if err := config.SetKexAlgorithms(strings.Join(defaultKexAlgorithms, ",")); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.KeyExchanges, defaultKexAlgorithms) {
		t.Error("configured algorithms do not preserve scanner default preference")
	}
	config = new(ssh.ClientConfig)
	config.SetDefaults()
	if !slices.Contains(config.KeyExchanges, "mlkem768x25519-sha256") {
		t.Error("library defaults do not offer hybrid KEX")
	}
	if err := config.SetKexAlgorithms("mlkem768x25519-sha256"); err != nil {
		t.Fatal(err)
	}
	if err := config.SetKexAlgorithms("unsupported-kex"); err == nil {
		t.Error("unsupported KEX was accepted")
	}
}
