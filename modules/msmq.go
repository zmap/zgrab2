package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/msmq"
)

func init() {
	zgrab2.RegisterModule(msmq.NewModule())
}
