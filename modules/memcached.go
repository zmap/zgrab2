package modules

import (
	"github.com/zmap/zgrab2/modules/memcached"
)

func init() {
	memcached.RegisterModule()
}
