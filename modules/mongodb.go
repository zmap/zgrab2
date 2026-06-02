package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/mongodb"
)

func init() {
	zgrab2.RegisterModule(mongodb.NewModule())
}
