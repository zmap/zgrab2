package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/rdp"
)

func init() {
	zgrab2.RegisterModule(rdp.NewModule())
}
