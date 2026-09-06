package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/msrpc"
)

func init() {
	zgrab2.RegisterModule(msrpc.NewModule())
}
