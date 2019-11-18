package bin

import "github.com/zmap/zgrab2"

// Summary holds the results of a run of a ZGrab2 binary.
type Summary struct {
	StatusesPerModule map[string]*zgrab2.State `json:"statuses"`
	StartTime         string                   `json:"start"`
	EndTime           string                   `json:"end"`
	Duration          string                   `json:"duration"`
}
