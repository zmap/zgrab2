package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/smtp"
)

func init() {
	zgrab2.RegisterModule(smtp.NewModule())
}
