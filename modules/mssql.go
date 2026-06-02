package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/mssql"
)

func init() {
	zgrab2.RegisterModule(mssql.NewModule())
}
