package modules

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/ssh"
)

type SSHFlags struct {
	zgrab2.BaseFlags      `group:"Basic Options"`
	ClientID              string `long:"client" description:"Specify the client ID string to use." default:"SSH-2.0-Go"`
	KexAlgorithms         string `long:"kex-algorithms" description:"A comma-separated list of kex algorithms to offer in descending precedence."`
	HostKeyAlgorithms     string `long:"host-key-algorithms" description:"A comma-separated list of host key algorithms to offer in descending precedence."`
	Ciphers               string `long:"ciphers" description:"A comma-separated list of cipher algorithms to offer in descending precedence."`
	MACs                  string `long:"macs" description:"A comma-separated list of MAC algorithms to offer in descending precedence."`
	CompressionAlgorithms string `long:"compression-algorithms" description:"A comma-separated list of compression algorithms to offer in decent precedence."`
	CollectExtensions     bool   `long:"extensions" description:"Complete the SSH transport layer protocol to collect SSH extensions as per RFC 8308 (if any)."`
	CollectUserAuth       bool   `long:"userauth" description:"Use the 'none' authentication request to see what userauth methods are allowed."`
	GexMinBits            uint   `long:"gex-min-bits" description:"The minimum number of bits for the DH GEX prime." default:"1024"`
	GexMaxBits            uint   `long:"gex-max-bits" description:"The maximum number of bits for the DH GEX prime." default:"8192"`
	GexPreferredBits      uint   `long:"gex-preferred-bits" description:"The preferred number of bits for the DH GEX prime." default:"2048"`
	HelloOnly             bool   `long:"hello-only" description:"Limit scan to the initial hello message."`
	OfferUnsupported      bool   `long:"offer-unsupported" description:"Offer unsupported connection algorithms during algorithm negotiation to maximize compatibility. With this flag active and no further algorithm choices, the SSH_MSG_KEXINIT message will increase by 63% in size (from 1200 bytes to 1952 bytes), causing fragmentation. This flag is mutually exclusive with flags that do not abort the connection before establishing the encrypted channel such as --extensions or --userauth."`
}

var defaultKexAlgorithms = []string{
	// Sorted by key size to reduce required bandwidth
	"curve25519-sha256",
	"curve25519-sha256@libssh.org",
	"ecdh-sha2-nistp256",
	"ecdh-sha2-nistp384",
	"ecdh-sha2-nistp521",
	"diffie-hellman-group1-sha1",
	"diffie-hellman-group14-sha256",
	"diffie-hellman-group14-sha1",
	// Group exchange requires 2 RTT rather than 1 RTT, therefore consider it last resort
	"diffie-hellman-group-exchange-sha256",
	"diffie-hellman-group-exchange-sha1",
}

var defaultHostKeyAlgorithms = []string{
	// Sorted by key and signature size to reduce required bandwidth
	"ssh-ed25519",
	"ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp384",
	"ecdsa-sha2-nistp521",
	"rsa-sha2-256",
	"rsa-sha2-512",
	"ssh-rsa",
	"ssh-dss",
	"ssh-ed25519-cert-v01@openssh.com",
	"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	"rsa-sha2-256-cert-v01@openssh.com",
	"rsa-sha2-512-cert-v01@openssh.com",
	"ssh-rsa-cert-v01@openssh.com",
	"ssh-dss-cert-v01@openssh.com",
}

var defaultCiphers = []string{
	"chacha20-poly1305@openssh.com",
	"aes128-gcm@openssh.com",
	"aes256-gcm@openssh.com",
	"aes128-ctr",
	"aes192-ctr",
	"aes256-ctr",
	"aes128-cbc",
	"arcfour256",
	"arcfour128",
	"arcfour",
	"3des-cbc",
}

var defaultCiphersWithUnsupported = append(defaultCiphers,
	// Unsupported ciphers
	// We exclude AEAD_AES_128_GCM and AEAD_AES_256_GCM due to the flawed algorithm negotiation.
	"chacha20-poly1305",
	"blowfish-cbc",
	"twofish256-cbc",
	"twofish-cbc",
	"twofish192-cbc",
	"twofish128-cbc",
	"aes256-cbc",
	"aes192-cbc",
	"serpent256-cbc",
	"serpent192-cbc",
	"serpent128-cbc",
	"idea-cbc",
	"cast128-cbc",
	"des-cbc",
	"3des-ctr",
	"blowfish-ctr",
	"twofish128-ctr",
	"twofish192-ctr",
	"twofish256-ctr",
	"serpent128-ctr",
	"serpent192-ctr",
	"serpent256-ctr",
	"idea-ctr",
	"cast128-ctr",
	"rijndael-cbc@lysator.liu.se",
	"seed-cbc@ssh.com",
	"none",
)

var defaultMacs = []string{
	"hmac-sha2-256-etm@openssh.com",
	"hmac-sha2-256",
	"hmac-sha1",
	"hmac-sha1-96",
}
var defaultMacsWithUnsupported = append(defaultMacs,
	// Unsupported ciphers
	// We exclude AEAD_AES_128_GCM and AEAD_AES_256_GCM due to the flawed algorithm negotiation.
	"hmac-sha2-512-etm@openssh.com",
	"hmac-sha2-512",
	"hmac-sha1-etm@openssh.com",
	"hmac-sha1-96-etm@openssh.com",
	"hmac-md5-etm@openssh.com",
	"hmac-md5",
	"hmac-md5-96-etm@openssh.com",
	"hmac-md5-96",
	"umac-32-etm@openssh.com",
	"umac-32@openssh.com",
	"umac-64-etm@openssh.com",
	"umac-64@openssh.com",
	"umac-96-etm@openssh.com",
	"umac-96@openssh.com",
	"umac-128-etm@openssh.com",
	"umac-128@openssh.com",
	"none",
)

var defaultCompressionAlgorithms = []string{
	"none",
}

var defaultCompressionAlgorithmsWithUnsupported = append(defaultCompressionAlgorithms,
	"zlib@openssh.com",
	"zlib",
)

type SSHModule struct {
}

type SSHScanner struct {
	config            *SSHFlags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

func init() {
	var sshModule SSHModule
	_, err := zgrab2.AddCommand("ssh", "Secure Shell (SSH)", sshModule.Description(), 22, &sshModule)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *SSHModule) NewFlags() any {
	return new(SSHFlags)
}

func (m *SSHModule) NewScanner() zgrab2.Scanner {
	return new(SSHScanner)
}

// Description returns an overview of this module.
func (m *SSHModule) Description() string {
	return "Fetch an SSH server banner and collect key exchange information"
}

func (f *SSHFlags) Validate(_ []string) error {
	return nil
}

func (f *SSHFlags) Help() string {
	return ""
}

func (s *SSHScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*SSHFlags)
	s.config = f
	if s.config.OfferUnsupported && (s.config.CollectExtensions || s.config.CollectUserAuth) {
		return errors.New("trying to offer unsupported algorithms while collecting extensions or user authentication methods")
	}
	if len(s.config.KexAlgorithms) == 0 {
		s.config.KexAlgorithms = strings.Join(defaultKexAlgorithms, ",")
	}
	if len(s.config.HostKeyAlgorithms) == 0 {
		s.config.HostKeyAlgorithms = strings.Join(defaultHostKeyAlgorithms, ",")
	}
	if len(s.config.Ciphers) == 0 {
		if s.config.OfferUnsupported {
			s.config.Ciphers = strings.Join(defaultCiphersWithUnsupported, ",")
		} else {
			s.config.Ciphers = strings.Join(defaultCiphers, ",")
		}
	}
	if len(s.config.MACs) == 0 {
		if s.config.OfferUnsupported {
			s.config.MACs = strings.Join(defaultMacsWithUnsupported, ",")
		} else {
			s.config.MACs = strings.Join(defaultMacs, ",")
		}
	}
	if len(s.config.CompressionAlgorithms) == 0 {
		if s.config.OfferUnsupported {
			s.config.CompressionAlgorithms = strings.Join(defaultCompressionAlgorithmsWithUnsupported, ",")
		} else {
			s.config.CompressionAlgorithms = strings.Join(defaultCompressionAlgorithms, ",")
		}
	}
	s.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

func (s *SSHScanner) InitPerSender(senderID int) error {
	return nil
}

func (s *SSHScanner) GetName() string {
	return s.config.Name
}

func (s *SSHScanner) GetTrigger() string {
	return s.config.Trigger
}

func (s *SSHScanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	data := new(ssh.HandshakeLog)
	portStr := strconv.Itoa(int(target.Port))
	rhost := net.JoinHostPort(target.Host(), portStr)

	sshConfig := new(ssh.ClientConfig)
	sshConfig.Timeout = s.config.ConnectTimeout
	sshConfig.ConnLog = data
	sshConfig.ClientVersion = s.config.ClientID
	sshConfig.HelloOnly = s.config.HelloOnly
	if err := sshConfig.SetKexAlgorithms(s.config.KexAlgorithms); err != nil {
		log.Fatal(err)
	}
	if err := sshConfig.SetHostKeyAlgorithms(s.config.HostKeyAlgorithms); err != nil {
		log.Fatal(err)
	}
	if err := sshConfig.SetCiphers(s.config.Ciphers, s.config.OfferUnsupported); err != nil {
		log.Fatal(err)
	}
	if err := sshConfig.SetMACs(s.config.MACs, s.config.OfferUnsupported); err != nil {
		log.Fatal(err)
	}
	if err := sshConfig.SetCompressionAlgorithms(s.config.CompressionAlgorithms, s.config.OfferUnsupported); err != nil {
		log.Fatal(err)
	}
	sshConfig.Verbose = s.config.Verbose
	sshConfig.CollectExtensions = s.config.CollectExtensions
	sshConfig.CollectUserAuth = s.config.CollectUserAuth
	sshConfig.DontAuthenticate = true // Ethical scanning only, never try to authenticate
	sshConfig.GexMinBits = s.config.GexMinBits
	sshConfig.GexMaxBits = s.config.GexMaxBits
	sshConfig.GexPreferredBits = s.config.GexPreferredBits
	sshConfig.BannerCallback = func(banner string) error {
		data.Banner = strings.TrimSpace(banner)
		return nil
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	// Implementation taken from lib/ssh/client.go
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		err = fmt.Errorf("failed to dial target %s: %w", target.String(), err)
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if s.config.ConnectTimeout != 0 {
		err = conn.SetDeadline(time.Now().Add(s.config.ConnectTimeout))
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("failed to set connection deadline: %w", err)
		}
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, rhost, sshConfig)
	if err != nil {
		return zgrab2.SCAN_HANDSHAKE_ERROR, nil, fmt.Errorf("failed to create SSH client connection: %w", err)
	}
	sshClient := ssh.NewClient(c, chans, reqs)
	defer func() {
		err = sshClient.Close()
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Errorf("error closing SSH client for target %s: %v", target.String(), err)
		}
	}()

	// TODO FIXME: Distinguish error types
	status := zgrab2.TryGetScanStatus(err)
	return status, data, err
}

// Protocol returns the protocol identifer for the scanner.
func (s *SSHScanner) Protocol() string {
	return "ssh"
}

func (s *SSHScanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return s.dialerGroupConfig
}

// GetScanMetadata returns any metadata on the scan itself from this module.
func (s *SSHScanner) GetScanMetadata() any {
	return nil
}
