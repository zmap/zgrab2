package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/checkpoint"
)

func init() {
	zgrab2.RegisterModule(checkpoint.NewModule())
}
