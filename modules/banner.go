package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/banner"
)

func init() {
	zgrab2.RegisterModule(banner.NewModule())
}
