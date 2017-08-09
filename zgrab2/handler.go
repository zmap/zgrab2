package zgrab2

// makeHandler will call GetBanner and respond with a protocol response, data unmarshalled, to the worker
func makeHandler(proto Protocol, m Monitor) (string, protocolResponse) {
	proto.PerRoutineInitialize()
	res, e := proto.Scan()
	var err *error //nil pointers are null in golang, which is not nil and not empty
	if e == nil {
		m.statuses <- status_success
		err = nil
	} else {
		m.statuses <- status_failure
		err = &e
	}
	resp := protocolResponse{Result: res, Error: err}
	return proto.GetName(), resp
}
