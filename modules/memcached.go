package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/memcached"
)

func init() {
	zgrab2.RegisterModule(memcached.NewModule())
}
