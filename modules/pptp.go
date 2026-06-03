package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/pptp"
)

func init() {
	zgrab2.RegisterModule(pptp.NewModule())
}
