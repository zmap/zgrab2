package main

import (
	"os"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/bin"

	"github.com/sirupsen/logrus"
)

func main() {
	modules := bin.NewModuleSetWithDefaults()
	globalFlags, err := zgrab2.ConfigFromCLI(os.Args[1:], modules)
	if err != nil {
		logrus.Fatalf("failed to parse CLI: %s", err)
	}
	if globalFlags == nil {
		// Help text was printed, exit quietly
		return
	}
	logrus.Infof("%v", globalFlags)
}
