package zgrab2

// makeHandler will call perRoutineInitialize, Scan, and respond with a protocol response, data unmarshalled, to the worker
func makeHandler(module Module, mon *Monitor) (string, moduleResponse) {
	module.PerRoutineInitialize()
	res, e := module.Scan()
	var err *error //nil pointers are null in golang, which is not nil and not empty
	if e == nil {
		mon.statusesChan <- moduleStatus{name: module.GetName(), st: status_success}
		err = nil
	} else {
		mon.statusesChan <- moduleStatus{name: module.GetName(), st: status_failure}
		err = &e
	}
	resp := moduleResponse{Result: res, Error: err}
	return module.GetName(), resp
}
