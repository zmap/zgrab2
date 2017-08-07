package zgrab2

import (
	"strconv"

	"github.com/ajholland/zflags"
	log "github.com/sirupsen/logrus"
)

type Protocol interface {
	GetBanner() (interface{}, error)
	Initialize()
	GetPort() uint
	GetName() string
}

type BaseProtocol struct {
	Port uint   `short:"p" long:"port" description:"Specify port to grab on" json:"port"`
	Name string `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple protocols" json:"-"`
}

func (b BaseProtocol) GetPort() uint {
	return b.Port
}

func (b BaseProtocol) GetName() string {
	return b.Name
}

func (b *BaseProtocol) SetDefaultPortAndName(cmd *flags.Command, port uint, name string) {
	cmd.FindOptionByLongName("port").Default = []string{strconv.FormatUint(uint64(port), 10)}
	cmd.FindOptionByLongName("name").Default = []string{name}
}

var lookups map[string]Protocol

func RegisterLookup(name string, p Protocol) {
	if lookups == nil {
		lookups = make(map[string]Protocol, 10)
	}
	//add to list and map
	if lookups[name] != nil {
		log.Fatal("name already used")
	}
	lookups[name] = p
}

func NumActions() uint {
	return uint(len(lookups))
}
