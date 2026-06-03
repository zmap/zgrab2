package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/siemens"
)

func init() {
	zgrab2.RegisterModule(siemens.NewModule())
}
