package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/drda"
)

func init() {
	zgrab2.RegisterModule(drda.NewModule())
}
