package zgrab2

import (
	"fmt"
	"log"
	"time"
)

var scanners map[string]*Scanner
var orderedScanners []string

// RegisterScan registers each individual scanner to be ran by the framework
func RegisterScan(name string, s Scanner) {
	//add to list and map
	if scanners[name] != nil {
		log.Fatalf("name: %s already used", name)
	}
	orderedScanners = append(orderedScanners, name)
	scanners[name] = &s
}

// PrintScanners prints all registered scanners
func PrintScanners() {
	for k, v := range scanners {
		fmt.Println(k, v)
	}
}

// RunScanner runs a single scan on a target and returns the resulting data
func RunScanner(s Scanner, mon *Monitor, target ScanTarget) (string, ScanResponse) {
	t := time.Now()
	status, res, e := s.Scan(target)
	var err *string
	if e == nil {
		mon.statusesChan <- moduleStatus{name: s.GetName(), st: statusSuccess}
		err = nil
	} else {
		mon.statusesChan <- moduleStatus{name: s.GetName(), st: statusFailure}
		errString := e.Error()
		err = &errString
	}
	resp := ScanResponse{Result: res, Protocol: s.Protocol(), Error: err, Timestamp: t.Format(time.RFC3339), Status: status}
	return s.GetName(), resp
}

func init() {
	scanners = make(map[string]*Scanner)
}
