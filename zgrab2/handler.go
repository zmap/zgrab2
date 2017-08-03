package zgrab2

// makeHandler will call GetBanner and respond with a protocol response, data unmarshalled, to the worker
func makeHandler(proto Protocol) (string, protocolResponse) {
	res, e := proto.GetBanner()
	var err *error //nil pointers are null in golang, which is not nil and not empty
	if e == nil {
		err = nil
	} else {
		err = &e
	}
	resp := protocolResponse{Result: res, Error: err}
	return proto.GetName(), resp
}
