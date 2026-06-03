package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/smb"
)

func init() {
	zgrab2.RegisterModule(smb.NewModule())
}
