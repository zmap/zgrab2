package zlib

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"reflect"
)

// Handler will send a protocol response, data unmarshalled, to the worker
func MakeHandler(response chan protocolResponse, opt int) {
	rv := reflect.ValueOf(Options[opt])
	t := reflect.ValueOf(Options[opt])

	for i := 0; i < t.NumField(); i++ {
		v := rv.Field(i)

		switch v.Kind() {
		case reflect.Struct:
			if v.Type().String() != "zlib.MultConfig" {
				method := v.MethodByName("GetBanner")
				p := v.MethodByName("GetPort")
				var port int64
				if p.IsValid() {
					port = p.Call([]reflect.Value{})[0].Int()
				} else {
					fmt.Println(v.Type())
					log.Fatal("Method GetPort not defined for interface")
				}
				if method.IsValid() {
					if port != -1 {
						method.Call([]reflect.Value{})
					}
				} else {
					fmt.Println(v.Type())
					log.Fatal("Method GetBanner not defined for interface")
				}
			}
		default:
			//fmt.Println(v.Kind())
		}
	}
}

/*
func (g *Worker) MakeHandler() Handler {
	return func(v interface{}) interface{} {

	}
}
*/
