package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/gesrtp"
)

func init() {
	zgrab2.RegisterModule(gesrtp.NewModule())
}
