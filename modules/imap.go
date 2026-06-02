package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/imap"
)

func init() {
	zgrab2.RegisterModule(imap.NewModule())
}
