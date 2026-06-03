package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/postgres"
)

func init() {
	zgrab2.RegisterModule(postgres.NewModule())
}
