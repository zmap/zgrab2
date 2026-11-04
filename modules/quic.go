package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/quic"
)

func init() {
	zgrab2.RegisterModule(quic.NewModule())
}
