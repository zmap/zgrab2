package zmodules

import (
	"net"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/zimports/ssh"
)

type SSHModule struct {
	zgrab2.BaseModule
	Client            string `long:"client" description:"Mimic behavior of a specific SSH client"`
	KexAlgorithms     string `long:"kex-algorithms" description:"Set SSH Key Exchange Algorithms"`
	HostKeyAlgorithms string `long:"host-key-algorithms" description:"Set SSH Host Key Algorithms"`
	NegativeOne       bool   `long:"negative-one" description:"Set SSH DH kex value to -1 in the selected group"`
}

func init() {
	var sshModule SSHModule
	cmd, err := zgrab2.AddCommand("ssh", "SSH Banner Grab", "Grab a banner over SSH", &sshModule)
	if err != nil {
		log.Fatal(err)
	}
	sshModule.SetDefaultPortAndName(cmd, uint(22), "ssh")
}

func (x *SSHModule) New() interface{} {
	return new(SSHModule)
}

// per module per routine initialization call
func (x *SSHModule) PerRoutineInitialize() {

}

// Execute validates the options sent to SSHModule and then passes operation back to main
func (x *SSHModule) Validate(args []string) error {
	zgrab2.RegisterLookup(x.Name, x)
	return nil
}

func (x *SSHModule) makeSSHGrabber(hlog *ssh.HandshakeLog) func(string) error {
	return func(netAddr string) error {
		sshConfig := ssh.MakeSSHConfig()
		sshConfig.Timeout = time.Duration(x.Timeout) * time.Second
		sshConfig.ConnLog = hlog
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
