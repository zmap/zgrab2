package zgrab2

import (
	"fmt"
	"log"
	"time"
)

type Scanner interface {
	// Init runs once for this module at library init time. It is passed the parsed command-line flags
	Init(name string, flags ScanFlags) error

	// InitPerSender runs once per Goroutine. A single Goroutine will scan some non-deterministics
	// subset of the input scan targets
	InitPerSender(senderID int) error

	// Returns the name passed at init
	GetName() string

	// Scan connects to a host. The result should be JSON-serializable
	Scan(t ScanTarget, port uint) (interface{}, error)
}

type ScanModule interface {
	// Called by the framework to pass to the argument parser. The parsed flags will be passed
	// to the scanner created by NewScanner().
	NewFlags() interface{}

	// Called by the framework for each time an individual scan is specified in the config or on
	// the command-line. The framework will then call scanner.Init(name, flags).
	NewScanner() interface{}
}

type ScanFlags interface {
	// Help optionally returns any additional help text, e.g. specifying what empty defaults
	// are interpreted as.
	Help() string

	// Validate enforces all command-line flags and positional arguments have valid values.
	Validate(args []string) error
}

type BaseFlags struct {
	Port    uint   `short:"p" long:"port" description:"Specify port to grab on"`
	Name    string `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple modules"`
	Timeout uint   `short:"t" long:"timeout" description:"Set connection timeout in seconds"`
}

func (b *BaseFlags) GetName() string {
	return b.Name
}

var scanners map[string]*Scanner
var orderedScanners []string

func init() {
	scanners = make(map[string]*Scanner)
}

func RegisterScanner(name string, s Scanner) {
	//add to list and map
	if scanners[name] != nil {
		log.Fatal("name already used")
	}
	orderedScanners = append(orderedScanners, name)
	scanners[name] = &s
	fmt.Println("Registered: ", name, s)
}

func PrintScanners() {
	for k, v := range scanners {
		fmt.Println(k, v)
	}
}

func RunModule(s Scanner, mon *Monitor, target ScanTarget) (string, ScanResponse) {
	t := time.Now()
	res, e := s.Scan(target, uint(22))
	var err *error //nil pointers are null in golang, which is not nil and not empty
	if e == nil {
		mon.statusesChan <- moduleStatus{name: s.GetName(), st: status_success}
		err = nil
	} else {
		mon.statusesChan <- moduleStatus{name: s.GetName(), st: status_failure}
		err = &e
	}
	resp := ScanResponse{Result: res, Error: err, Time: t.Format(time.RFC3339)}
	return s.GetName(), resp
}
