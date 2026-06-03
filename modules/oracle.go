package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/oracle"
)

func init() {
	zgrab2.RegisterModule(oracle.NewModule())
}
