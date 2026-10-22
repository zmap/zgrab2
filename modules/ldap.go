package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/ldap"
)

func init() {
	zgrab2.RegisterModule(ldap.NewModule())
}
