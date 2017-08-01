package zgrab2

// makeHandler will call GetBanner and respond with a protocol response, data unmarshalled, to the worker
func makeHandler(proto Protocol) (string, protocolResponse) {
	res, e := proto.GetBanner()
	resp := protocolResponse{result: res, err: e}
	return proto.GetName(), resp
}
