package zgrab2

import (
	"log"
	"net"
	"strconv"

	"github.com/ajholland/zflags"
)

type Module interface {
	Scan(ip net.IP) (interface{}, error)
	PerRoutineInitialize()
	GetPort() uint
	GetName() string
	New() interface{}
	Validate(args []string) error
}

type BaseModule struct {
	Port    uint   `short:"p" long:"port" description:"Specify port to grab on"`
	Name    string `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple modules"`
	Timeout int    `short:"t" long:"timeout" description:"Set connection timeout in seconds"`
}

func (b *BaseModule) GetPort() uint {
	return b.Port
}

func (b *BaseModule) GetName() string {
	return b.Name
}

func (b *BaseModule) SetDefaultPortAndName(cmd *flags.Command, port uint, name string) {
	cmd.FindOptionByLongName("port").Default = []string{strconv.FormatUint(uint64(port), 10)}
	cmd.FindOptionByLongName("name").Default = []string{name}
}

var modules map[string]*Module

func init() {
	modules = make(map[string]*Module)
}

func RegisterModule(name string, m Module) {
	//add to list and map
	if modules[name] != nil {
		log.Fatal("name already used")
	}

	modules[name] = &m
}
