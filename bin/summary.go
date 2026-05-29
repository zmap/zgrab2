package bin

import "github.com/zmap/zgrab2"

// Metadata holds the results of a run of a ZGrab2 binary.
type Metadata struct {
	PerModuleMetadata map[string]*zgrab2.ModuleMetadata `json:"statuses"`
	StartTime         string                            `json:"start"`
	EndTime           string                            `json:"end"`
	Duration          string                            `json:"duration"`
	CLIInvocation     string                            `json:"zgrab_cli_parameters,omitempty"`
	NumTargetsScanned uint                              `json:"num_targets_scanned"`
}
