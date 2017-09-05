package zgrab2

import (
	"log"
	"net"
	"strconv"
	"time"

	"github.com/ajholland/zflags"
)

// ScanModule is the interface that every module to zgrab2 must support in order to be run
type ScanModule interface {
	Scan(ip net.IP) (interface{}, error)
	PerRoutineInitialize()
	GetPort() uint
	GetName() string
	New() interface{}
	Validate(args []string) error
}

// BaseScanModule is a base struct that every module must embed
type BaseScanModule struct {
	// Port represents the port that the module will grab on
	Port uint `short:"p" long:"port" description:"Specify port to grab on"`

	// Name is the name of each type of module
	Name string `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple modules"`

	// Timeout is the length of time before quitting the connection
	Timeout int `short:"t" long:"timeout" description:"Set connection timeout in seconds"`
}

// GetPort returns the port that the module will grab on
func (b *BaseScanModule) GetPort() uint {
	return b.Port
}

// GetName returns the name of the specific module
func (b *BaseScanModule) GetName() string {
	return b.Name
}

// SetDefaultPortAndName sets the default port and name that are used by the imported flags library
func (b *BaseScanModule) SetDefaultPortAndName(cmd *flags.Command, port uint, name string) {
	cmd.FindOptionByLongName("port").Default = []string{strconv.FormatUint(uint64(port), 10)}
	cmd.FindOptionByLongName("name").Default = []string{name}
}

var modules map[string]*ScanModule
var orderedModules []string

func init() {
	modules = make(map[string]*ScanModule)
}

// RegisterModule adds the specified ScanModule as a value to a global map with its
// name as the key. It also ads the speciifed ScanModule's name to a global list of modules
// in order to maintain sequential ordering of modules.
func RegisterModule(name string, m ScanModule) {
	//add to list and map
	if modules[name] != nil {
		log.Fatal("name already used")
	}
	orderedModules = append(orderedModules, name)
	modules[name] = &m
}

// RunModule initializes and scans the module, it then reports its status to the monitor and
// returns a result and the modules name
func RunModule(module ScanModule, mon *monitor, ip net.IP) (string, ModuleResponse) {
	t := time.Now()
	module.PerRoutineInitialize()
	res, e := module.Scan(ip)
	var err *error //nil pointers are null in golang, which is not nil and not empty
	if e == nil {
		mon.statusesChan <- moduleStatus{name: module.GetName(), st: statusSuccess}
		err = nil
	} else {
		mon.statusesChan <- moduleStatus{name: module.GetName(), st: statusFailure}
		err = &e
	}
	resp := ModuleResponse{Result: res, Error: err, Time: t.Format(time.RFC3339)}
	return module.GetName(), resp
}
