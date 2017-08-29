package zgrab2

import (
	"net"
	"time"
)

// runHandler will call perRoutineInitialize, Scan, and respond with a protocol response, data unmarshalled, to the worker
func runHandler(module Module, mon *Monitor, ip net.IP) (string, moduleResponse) {
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
	resp := moduleResponse{Result: res, Error: err, Time: t.Format(time.RFC3339)}
	return module.GetName(), resp
}
