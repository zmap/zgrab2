package zgrab2

import (
	flags "github.com/zmap/zflags"
)

func ConfigFromCLI(args []string, modules ModuleSet) (*GlobalFlags, error) {
	globalFlags := GlobalFlags{}
	parser := flags.NewParser(&globalFlags, flags.Default)
	for moduleName, m := range modules {
		_, err := parser.AddCommand(moduleName, m.Description(), "", m)
		if err != nil {
			return nil, err
		}
	}
	posArgs, commandName, subflags, err := parser.ParseCommandLine(args)
	if err != nil {
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			return nil, nil
		}
		return nil, err
	}
	logger := globalFlags.InitLogging()
	logger.Debug(posArgs)
	logger.Debug(commandName)
	logger.Debug(subflags)
	return &globalFlags, nil
}
