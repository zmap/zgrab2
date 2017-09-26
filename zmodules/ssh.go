package zmodules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type SSHFlags struct {
	zgrab2.BaseFlags
	ClientID          string `long:"client" description:"Specify the client ID string to use" default:"SSH-2.0-Go"`
	KexAlgorithms     string `long:"kex-algorithms" description:"Set SSH Key Exchange Algorithms"`
	HostKeyAlgorithms string `long:"host-key-algorithms" description:"Set SSH Host Key Algorithms"`
	NegativeOne       bool   `long:"negative-one" description:"Set SSH DH kex value to -1 in the selected group"`
}

type SSHModule struct {
}

type SSHScanner struct {
	SSHFlags
}

func init() {
	var sshModule SSHModule
	_, err := zgrab2.AddCommand("ssh", "SSH Banner Grab", "Grab a banner over SSH", 22, &sshModule)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *SSHModule) NewFlags() ScanFlags {
	return new(SSHFlags)
}

func (m *SSHModule) NewScanner() Scanner {
	return new(SSHScanner)
}

func (f *SSHFlags) Validate(args []string) error {
	return nil
}

func (f *SSHFlags) Help() string {
	return ""
}

func (s *SSHScanner) Init(name string, flags interface{}) error {
	sshFlags := flags.(*SSHFlags)
	// set vars based on flags
	zgrab2.RegisterScanner(name, s)
	return nil
}

func (s *SSHScanner) InitPerSender(senderID int) error {
	return nil
}

func (s *SSHScanner) GetName() string {
	return ""
}
func (s *SSHScanner) Scan(t zgrab2.ScanTarget, port uint) (interface{}, error) {
	return nil, nil
}
