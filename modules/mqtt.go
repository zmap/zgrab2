package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/mqtt"
)

func init() {
	zgrab2.RegisterModule(mqtt.NewModule())
}
