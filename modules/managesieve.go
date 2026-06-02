package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/managesieve"
)

func init() {
	zgrab2.RegisterModule(managesieve.NewModule())
}
