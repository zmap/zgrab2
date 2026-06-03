package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/enip"
)

func init() {
	zgrab2.RegisterModule(enip.NewModule())
}
