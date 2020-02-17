package zgrab2

import (
	"fmt"

	flags "github.com/zmap/zflags"
)

func ConfigFromCLI(args []string, modules ModuleSet) (*GlobalFlags, error) {
	globalFlags := GlobalFlags{}
	parser := flags.NewParser(&globalFlags, flags.Default)
	for moduleName, m := range modules {
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
	logger := globalFlags.InitLogging()
	logger.Debug(posArgs)
	logger.Debug(commandName)
	logger.Debug(subflags)
	return nil, nil
}
