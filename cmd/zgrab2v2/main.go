package main

import (
	"os"
	"time"

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
	logger := globalFlags.InitLogging()
	logger.Infof("%v", globalFlags)
	in, err := globalFlags.OpenInputSource()
	if err != nil {
		logger.Fatalf("failed to open input: %s", err)
	}
	logger.Infof("using input: %s", globalFlags.InputFlags.Describe())
	env := zgrab2.Environment{
		Input: in,
	}
	logger.Infof("%v", env)
	start := time.Now()
	logger.Infof("started ZGrab2 at %s", start.Format(time.RFC3339))
	env.Start()
	env.Wait()
	end := time.Now()
	logger.Infof("finished ZGrab2 at %s", end.Format(time.RFC3339))
}
