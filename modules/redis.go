package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/redis"
)

func init() {
	zgrab2.RegisterModule(redis.NewModule())
}
