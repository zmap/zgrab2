package modules

import (
	"github.com/zmap/zgrab2/modules/http_proxy"
)

func init() {
	http_proxy.RegisterModule()
}
