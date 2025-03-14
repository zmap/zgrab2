package zgrab2

import (
	"context"
	"fmt"
	"log"
	"time"
)

var scanners map[string]*Scanner
var orderedScanners []string
var defaultDialerGroupToScanners map[string]*DialerGroup
var defaultDialerGroupConfigToScanners map[string]*DialerGroupConfig

// RegisterScan registers each individual scanner to be ran by the framework
func RegisterScan(name string, s Scanner) {
	//add to list and map
	if scanners[name] != nil || defaultDialerGroupToScanners[name] != nil {
		log.Fatalf("name: %s already used", name)
	}
	orderedScanners = append(orderedScanners, name)
	dialerConfig := s.GetDialerGroupConfig()
	if dialerConfig == nil {
		log.Fatalf("no dialer config for %s", name)
	}
	if err := dialerConfig.Validate(); err != nil {
		log.Fatalf("error validating dialer config for %s: %v", name, err)
	}
	defaultDialerGroupConfigToScanners[name] = dialerConfig
	dialerGroup, err := dialerConfig.getDefaultDialerGroupFromConfig()
	if err != nil {
		log.Fatalf("error getting default dialer group for %s: %v", name, err)
	}
	defaultDialerGroupToScanners[name] = dialerGroup
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
	dialerGroupConfig, ok := defaultDialerGroupConfigToScanners[s.GetName()]
	if !ok {
		log.Fatalf("no default dialer group config for %s", s.GetName())
	}
	dialerGroup, ok := defaultDialerGroupToScanners[s.GetName()]
	if !ok {
		log.Fatalf("no default dialer group for %s", s.GetName())
	}
	// if target's port isn't set, use default. Won't affect the caller's ScanTarget since it's passed by value
	if target.Port == 0 {
		target.Port = dialerGroupConfig.BaseFlags.Port
	}

	status, res, e := s.Scan(context.Background(), dialerGroup, &target)
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
	defaultDialerGroupToScanners = make(map[string]*DialerGroup)
	defaultDialerGroupConfigToScanners = make(map[string]*DialerGroupConfig)
}
