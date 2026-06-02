package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/socks5"
)

func init() {
	zgrab2.RegisterModule(socks5.NewModule())
}
