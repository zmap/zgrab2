package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/snmp"
)

func init() {
	zgrab2.RegisterModule(snmp.NewModule())
}
