package zgrab2

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/ajholland/zflags"
)

type ScanModule interface {
	Scan(ip net.IP) (interface{}, error)
	PerRoutineInitialize()
	GetPort() uint
	GetName() string
	New() interface{}
	Validate(args []string) error
}

type BaseScanModule struct {
	Port    uint   `short:"p" long:"port" description:"Specify port to grab on"`
	Name    string `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple modules"`
	Timeout int    `short:"t" long:"timeout" description:"Set connection timeout in seconds"`
}

func (b *BaseScanModule) GetPort() uint {
	return b.Port
}

func (b *BaseScanModule) GetName() string {
	return b.Name
}

func (b *BaseScanModule) SetDefaultPortAndName(cmd *flags.Command, port uint, name string) {
	cmd.FindOptionByLongName("port").Default = []string{strconv.FormatUint(uint64(port), 10)}
	cmd.FindOptionByLongName("name").Default = []string{name}
}

var modules map[string]*ScanModule
var orderedModules []string

func init() {
	modules = make(map[string]*ScanModule)
}

func RegisterModule(name string, m ScanModule) {
	//add to list and map
	if modules[name] != nil {
		log.Fatal("name already used")
	}
	orderedModules = append(orderedModules, name)
	modules[name] = &m
}

// runHandler will call perRoutineInitialize, Scan, and respond with a protocol response, data unmarshalled, to the worker
func RunModule(module ScanModule, mon *Monitor, ip net.IP) (string, ModuleResponse) {
	t := time.Now()
	module.PerRoutineInitialize()
	res, e := module.Scan(ip)
	var err *error //nil pointers are null in golang, which is not nil and not empty
	if e == nil {
		mon.statusesChan <- moduleStatus{name: module.GetName(), st: status_success}
		err = nil
	} else {
		mon.statusesChan <- moduleStatus{name: module.GetName(), st: status_failure}
		err = &e
	}
	resp := ModuleResponse{Result: res, Error: err, Time: t.Format(time.RFC3339)}
	return module.GetName(), resp
}
