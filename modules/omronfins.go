package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/omronfins"
)

func init() {
	zgrab2.RegisterModule(omronfins.NewModule())
}
