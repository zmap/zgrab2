package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/ntp"
)

func init() {
	zgrab2.RegisterModule(ntp.NewModule())
}
