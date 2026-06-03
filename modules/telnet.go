package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/telnet"
)

func init() {
	zgrab2.RegisterModule(telnet.NewModule())
}
