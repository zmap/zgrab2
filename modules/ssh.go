package modules

import (
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/ssh"
)

type SSHFlags struct {
	zgrab2.BaseFlags  `group:"Basic Options"`
	ClientID          string `long:"client" description:"Specify the client ID string to use" default:"SSH-2.0-Go"`
	KexAlgorithms     string `long:"kex-algorithms" description:"Set SSH Key Exchange Algorithms"`
	HostKeyAlgorithms string `long:"host-key-algorithms" description:"Set SSH Host Key Algorithms"`
	Ciphers           string `long:"ciphers" description:"A comma-separated list of which ciphers to offer."`
	CollectExtensions bool   `long:"extensions" description:"Complete the SSH transport layer protocol to collect SSH extensions as per RFC 8308 (if any)."`
	CollectUserAuth   bool   `long:"userauth" description:"Use the 'none' authentication request to see what userauth methods are allowed"`
	GexMinBits        uint   `long:"gex-min-bits" description:"The minimum number of bits for the DH GEX prime." default:"1024"`
	GexMaxBits        uint   `long:"gex-max-bits" description:"The maximum number of bits for the DH GEX prime." default:"8192"`
	GexPreferredBits  uint   `long:"gex-preferred-bits" description:"The preferred number of bits for the DH GEX prime." default:"2048"`
	HelloOnly         bool   `long:"hello-only" description:"Limit scan to the initial hello message"`
	Verbose           bool   `long:"verbose" description:"Output additional information, including SSH client properties from the SSH handshake."`
}

type SSHModule struct {
}

type SSHScanner struct {
	config *SSHFlags
}

func init() {
	var sshModule SSHModule
	_, err := zgrab2.AddCommand("ssh", "SSH Banner Grab", sshModule.Description(), 22, &sshModule)
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

func (f *SSHFlags) Validate(args []string) error {
	return nil
}

func (f *SSHFlags) Help() string {
	return ""
}

func (s *SSHScanner) Init(flags zgrab2.ScanFlags) error {
	sc := ssh.MakeSSHConfig() //dummy variable to get default for host key, kex algorithm, ciphers
	f, _ := flags.(*SSHFlags)
	s.config = f
	if len(s.config.Ciphers) == 0 {
		s.config.Ciphers = string(strings.Join(sc.Ciphers, ","))
	}
	if len(s.config.KexAlgorithms) == 0 {
		s.config.KexAlgorithms = string(strings.Join(sc.KeyExchanges, ","))
	}
	if len(s.config.HostKeyAlgorithms) == 0 {
		s.config.HostKeyAlgorithms = string(strings.Join(sc.HostKeyAlgorithms, ","))
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

func (s *SSHScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	data := new(ssh.HandshakeLog)

	var port uint
	// If the port is supplied in ScanTarget, let that override the cmdline option
	if t.Port != nil {
		port = *t.Port
	} else {
		port = s.config.Port
	}
	portStr := strconv.FormatUint(uint64(port), 10)
	rhost := net.JoinHostPort(t.Host(), portStr)

	sshConfig := ssh.MakeSSHConfig()
	sshConfig.Timeout = s.config.Timeout
	sshConfig.ConnLog = data
	sshConfig.ClientVersion = s.config.ClientID
	sshConfig.HelloOnly = s.config.HelloOnly
	if err := sshConfig.SetHostKeyAlgorithms(s.config.HostKeyAlgorithms); err != nil {
		log.Fatal(err)
	}
	if err := sshConfig.SetKexAlgorithms(s.config.KexAlgorithms); err != nil {
		log.Fatal(err)
	}
	if err := sshConfig.SetCiphers(s.config.Ciphers); err != nil {
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
	_, err := ssh.Dial("tcp", rhost, sshConfig)
	// TODO FIXME: Distinguish error types
	status := zgrab2.TryGetScanStatus(err)
	return status, data, err
}

// Protocol returns the protocol identifer for the scanner.
func (s *SSHScanner) Protocol() string {
	return "ssh"
}
