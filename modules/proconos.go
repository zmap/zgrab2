package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/proconos"
)

func init() {
	zgrab2.RegisterModule(proconos.NewModule())
}
