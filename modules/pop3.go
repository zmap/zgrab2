package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/pop3"
)

func init() {
	zgrab2.RegisterModule(pop3.NewModule())
}
