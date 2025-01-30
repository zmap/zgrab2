package main

import (
	"github.com/zmap/zgrab2/bin"
	"github.com/zmap/zgrab2/modules/http"
	"github.com/zmap/zgrab2/modules/ipp"
	"github.com/zmap/zgrab2/modules/ntp"

	// TODO Phillip testing
	_ "github.com/zmap/zgrab2/modules/http"
	_ "github.com/zmap/zgrab2/modules/ipp"
	_ "github.com/zmap/zgrab2/modules/ntp"
)

// main wraps the "true" main, bin.ZGrab2Main(), after importing all scan
// modules in ZGrab2.
func main() {
	http.RegisterModule()
	ipp.RegisterModule()
	ntp.RegisterModule()
	bin.ZGrab2Main()
}
