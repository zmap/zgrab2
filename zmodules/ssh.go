package zmodules

import (
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/zimports/ssh"
)

type SSHModule struct {
	zgrab2.BaseScanModule
	ClientID          string `long:"client" description:"Specify the client ID string to use" default:"SSH-2.0-Go"`
	KexAlgorithms     string `long:"kex-algorithms" description:"A comma-separated list of which DH key exchange algorithms to offer"`
	HostKeyAlgorithms string `long:"host-key-algorithms" description:"A comma-separated list of which host key algorithms to offer"`
	Ciphers           string `long:"ciphers" description:"A comma-separated list of which ciphers to offer"`
	Verbose           bool   `long:"verbose" description:"Output additional information, including SSH client properties from the SSH handshake."`
	CollectUserAuth   bool   `long:"userauth" description:"Use the 'none' authentication request to see what userauth methods are allowed."`
	GexMinBits        uint   `long:"gex-min-bits" description:"The minimum number of bits for the DH GEX prime." default:"1024"`
	GexMaxBits        uint   `long:"gex-max-bits" description:"The maximum number of bits for the DH GEX prime." default:"8192"`
	GexPreferredBits  uint   `long:"gex-preferred-bits" description:"The preferred number of bits for the DH GEX prime." default:"2048"`
}

func init() {
	var sshModule SSHModule
	cmd, err := zgrab2.AddCommand("ssh", "SSH Banner Grab", "Grab a banner over SSH", &sshModule)
	if err != nil {
		log.Fatal(err)
	}
	sshModule.SetDefaultPortAndName(cmd, uint(22), "ssh")
	s := ssh.MakeSSHConfig() //dummy variable to get default for host key, kex algorithm, ciphers
	cmd.FindOptionByLongName("host-key-algorithms").Default = []string{strings.Join(s.HostKeyAlgorithms, ",")}
	cmd.FindOptionByLongName("kex-algorithms").Default = []string{strings.Join(s.KeyExchanges, ",")}
	cmd.FindOptionByLongName("ciphers").Default = []string{strings.Join(s.Ciphers, ",")}
}

func (x *SSHModule) New() interface{} {
	return new(SSHModule)
}

// per module per routine initialization call
func (x *SSHModule) PerRoutineInitialize() {

}

// Validate checks all variables for validity and then registers the module with zgrab2
func (x *SSHModule) Validate(args []string) error {
	zgrab2.RegisterModule(x.Name, x)
	return nil
}

func (x *SSHModule) makeSSHGrabber(hlog *ssh.HandshakeLog) func(string) error {
	return func(netAddr string) error {
		sshConfig := ssh.MakeSSHConfig()
		sshConfig.Timeout = time.Duration(x.Timeout) * time.Second
		sshConfig.ConnLog = hlog
		sshConfig.ClientVersion = x.ClientID
		sshConfig.HostKeyAlgorithms = strings.Split(x.HostKeyAlgorithms, ",")
		sshConfig.KeyExchanges = strings.Split(x.KexAlgorithms, ",")
		sshConfig.Ciphers = strings.Split(x.Ciphers, ",")
		sshConfig.Verbose = x.Verbose
		sshConfig.DontAuthenticate = x.CollectUserAuth
		sshConfig.GexMinBits = x.GexMinBits
		sshConfig.GexMaxBits = x.GexMaxBits
		sshConfig.GexPreferredBits = x.GexPreferredBits
		_, err := ssh.Dial("tcp", netAddr, sshConfig)
		if err != nil {
			return err
		}

		return nil
	}
}

func (x *SSHModule) Scan(ip net.IP) (interface{}, error) {
	data := new(ssh.HandshakeLog)
	sshGrabber := x.makeSSHGrabber(data)

	port := strconv.FormatUint(uint64(x.Port), 10)
	rhost := net.JoinHostPort(ip.String(), port)

	err := sshGrabber(rhost)

	return data, err
}
