package zlib

import (
	log "github.com/sirupsen/logrus"
	"reflect"
)

type Protocol interface {
	GetPort() int64
	GetBanner() interface{}
	GetName() string
}

// MakeHandler will call GetBanner and send a protocol response, data unmarshalled, to the worker
func MakeHandler(response chan protocolResponse, opt int) {
	rv := reflect.ValueOf(Options[opt])
	t := reflect.ValueOf(Options[opt])
	for i := 0; i < t.NumField(); i++ {
		v := rv.Field(i)
		switch v.Kind() {
		case reflect.Struct:
			if v.Type().String() != "zlib.MultConfig" {
				if p := v.MethodByName("GetPort"); p.IsValid() {
					if port := p.Call([]reflect.Value{})[0].Int(); port != -1 {
						method := v.MethodByName("GetBanner")
						name := v.MethodByName("GetName")
						if method.IsValid() && name.IsValid() {
							res := method.Call([]reflect.Value{})[0].Interface()
							protocolName := name.Call([]reflect.Value{})[0].String()
							r := protocolResponse{protocol: protocolName, result: res}
							response <- r
						} else {
							log.Fatal("Method not defined for interface")
						}
					}
				} else {
					log.Fatal("Method GetPort not defined for interface")
				}
			}
		}
	}
}
