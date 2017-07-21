package zlib

type SSHConfig struct {
	Port              int    `short:"p" long:"port" default:"22" description:"Specify port to grab on" json:"port"`
	Name              string `short:"n" long:"name" default:"ssh" description:"Specify name for output json, only necessary if scanning multiple protocols" json:"-"`
	Client            string `long:"client" description:"Mimic behavior of a specific SSH client" json:"client"`
	KexAlgorithms     string `long:"kex-algorithms" description:"Set SSH Key Exchange Algorithms" json:"kex"`
	HostKeyAlgorithms string `long:"host-key-algorithms" description:"Set SSH Host Key Algorithms" json:"hostkey"`
	NegativeOne       bool   `long:"negative-one" description:"Set SSH DH kex value to -1 in the selected group" json:"negativeone"`

	scan bool
}

// Execute validates the options sent to SSHConfig and then passes operation back to main
func (x *SSHConfig) Execute(args []string) error {
	validateHighLevel()
	x.scan = true
	return nil
}

func (x SSHConfig) GetName() string {
	return x.Name
}

func (x SSHConfig) GetPort() int {
	return x.Port
}

func (x SSHConfig) GetScan() bool {
	return x.scan
}

func (x SSHConfig) GetBanner() SSHConfig {
	return x
}
