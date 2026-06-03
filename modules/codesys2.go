package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/codesys2"
)

func init() {
	zgrab2.RegisterModule(codesys2.NewModule())
}
