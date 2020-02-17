package bin

import (
	"fmt"

	"github.com/sirupsen/logrus"
	flags "github.com/zmap/zflags"
	"github.com/zmap/zgrab2"
)

func ConfigFromCLI(args []string, knownModules map[string]zgrab2.ScanModule) (*zgrab2.GlobalFlags, error) {
	globalFlags := zgrab2.GlobalFlags{}
	parser := flags.NewParser(&globalFlags, flags.Default)
	for moduleName, m := range knownModules {
		// TODO: Pass descriptions through module definition
		shortDescription := fmt.Sprintf("%s - short", moduleName)
		longDescription := fmt.Sprintf("%s - long", moduleName)
		_, err := parser.AddCommand(moduleName, shortDescription, longDescription, m)
		if err != nil {
			return nil, err
		}
	}
	posArgs, commandName, subflags, err := parser.ParseCommandLine(args)
	if err != nil {
		return nil, err
	}
	logrus.Debug(posArgs)
	logrus.Debug(commandName)
	logrus.Debug(subflags)
	return nil, nil
}
