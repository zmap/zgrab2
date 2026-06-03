package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/fox"
)

func init() {
	zgrab2.RegisterModule(fox.NewModule())
}
