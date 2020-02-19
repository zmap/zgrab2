package zgrab2

import (
	"fmt"

	flags "github.com/zmap/zflags"
)

func ConfigFromCLI(args []string, modules ModuleSet) (*GlobalFlags, []Scanner, error) {
	globalFlags := GlobalFlags{}
	parser := flags.NewParser(&globalFlags, flags.Default)
	for moduleName, m := range modules {
		_, err := parser.AddCommand(moduleName, m.Description(), "", m)
		if err != nil {
			return nil, nil, err
		}
	}
	posArgs, commandName, subflags, err := parser.ParseCommandLine(args)
	if err != nil {
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	logger := globalFlags.InitLogging()
	logger.Debug(posArgs)
	logger.Debug(commandName)
	logger.Debug(subflags)
	mod, ok := modules[commandName]
	if !ok {
		// This shouldn't happen because we matched the parser to the ModuleSet
		return &globalFlags, nil, fmt.Errorf("unknown module: %s", commandName)
	}
	scanFlags, ok := subflags.(ScanFlags)
	if !ok {
		// This shouldn't happen because we matched the data to the Module type
		return &globalFlags, nil, fmt.Errorf("unknown flag type returned for module %s", commandName)
	}
	scanner := mod.NewScanner()
	scanner.Init(scanFlags)
	scanners := []Scanner{
		scanner,
	}
	return &globalFlags, scanners, nil
}
