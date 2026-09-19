package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/codesysv3"
)

func init() {
	zgrab2.RegisterModule(codesysv3.NewModule())
}
