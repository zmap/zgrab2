package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/amqp091"
)

func init() {
	zgrab2.RegisterModule(amqp091.NewModule())
}
