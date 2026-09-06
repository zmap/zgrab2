package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/pcworx"
)

func init() {
	zgrab2.RegisterModule(pcworx.NewModule())
}
