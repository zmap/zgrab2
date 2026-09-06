package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/crimson"
)

func init() {
	zgrab2.RegisterModule(crimson.NewModule())
}
