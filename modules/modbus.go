package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/modbus"
)

func init() {
	zgrab2.RegisterModule(modbus.NewModule())
}
