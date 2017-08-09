package zmodules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2/zgrab2"
)

type SSHConfig struct {
	zgrab2.BaseModule
	Client            string `long:"client" description:"Mimic behavior of a specific SSH client"`
	KexAlgorithms     string `long:"kex-algorithms" description:"Set SSH Key Exchange Algorithms"`
	HostKeyAlgorithms string `long:"host-key-algorithms" description:"Set SSH Host Key Algorithms"`
	NegativeOne       bool   `long:"negative-one" description:"Set SSH DH kex value to -1 in the selected group"`
}

func init() {
	var sshConfig SSHConfig
	cmd, err := zgrab2.AddCommand("ssh", "SSH Banner Grab", "Grab a banner over SSH", &sshConfig)
	if err != nil {
		log.Fatal(err)
	}
	sshConfig.SetDefaultPortAndName(cmd, uint(22), "ssh")
}

// per module per routine initialization call
func (x SSHConfig) PerRoutineInitialize() {

}

// Execute validates the options sent to SSHConfig and then passes operation back to main
func (x *SSHConfig) Validate(args []string) error {
	zgrab2.RegisterLookup(x.Name, *x)
	return nil
}

func (x SSHConfig) Scan() (interface{}, error) {
	return x, nil
}
