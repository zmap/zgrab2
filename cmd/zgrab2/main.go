package main

import (
	"github.com/zmap/zgrab2/bin"
	_ "github.com/zmap/zgrab2/modules"
)

// main wraps the "true" main, bin.ZGrab2Main(), after importing all scan
// modules in ZGrab2.
func main() {
	bin.ZGrab2Main()
}
