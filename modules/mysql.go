package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/mysql"
)

func init() {
	zgrab2.RegisterModule(mysql.NewModule())
}
