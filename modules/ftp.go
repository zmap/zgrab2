package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/ftp"
)

func init() {
	zgrab2.RegisterModule(ftp.NewModule())
}
