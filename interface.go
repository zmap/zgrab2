package zgrab2

import (
	"fmt"
	"strconv"

	"github.com/ajholland/zflags"
	log "github.com/sirupsen/logrus"
)

type Module interface {
	Scan() (interface{}, error)
	PerRoutineInitialize()
	GetPort() uint
	GetName() string
}

type BaseModule struct {
	Port uint   `short:"p" long:"port" description:"Specify port to grab on"`
	Name string `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple modules"`
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

var lookups map[string]*Module

func RegisterLookup(name string, m Module) {
	if lookups == nil {
		lookups = make(map[string]*Module, 10)
	}
	//add to list and map
	if lookups[name] != nil {
		log.Fatal("name already used")
	}

	lookups[name] = &m
}

func PrintLookup() {
	for k, v := range lookups {
		fmt.Println(k, *v)
	}
}
