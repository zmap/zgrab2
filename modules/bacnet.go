package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/bacnet"
)

func init() {
	zgrab2.RegisterModule(bacnet.NewModule())
}
