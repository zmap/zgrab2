package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/dnp3"
)

func init() {
	zgrab2.RegisterModule(dnp3.NewModule())
}
