package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/jarm"
)

func init() {
	zgrab2.RegisterModule(jarm.NewModule())
}
