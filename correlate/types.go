// Package correlate builds a per-host, cross-protocol attack-surface
// assessment from the output of `zgrab2 multiple` (see processing.go's
// Grab struct), combining independent per-module results (msmq, msrpc, smb,
// rdp) into host-level OS-family/version and vulnerability conclusions.
//
// The core rule this package enforces: any single protocol module's own
// output (see lib/attribution) never claims OS family/version on its own.
// This package is where that corroboration is allowed to happen, and only
// when at least one protocol provides genuine evidence -- absence of a
// service (closed/timeout/not_observed/not_scanned) never counts as
// negative evidence, and no vulnerability status is ever escalated beyond
// what the underlying per-module evidence already supports (this package
// does not maintain a version-to-CVE mapping).
package correlate

import "encoding/json"

// scanResponse mirrors zgrab2.ScanResponse (see module.go), but keeps
// Result as raw JSON so it can be decoded into the correct concrete type
// once Protocol is known.
type scanResponse struct {
	Status    string          `json:"status"`
	Protocol  string          `json:"protocol"`
	Port      uint            `json:"port"`
	Result    json.RawMessage `json:"result,omitempty"`
	Timestamp string          `json:"timestamp,omitempty"`
	Error     *string         `json:"error,omitempty"`
}

// grabRecord mirrors processing.Grab, the per-host record emitted by
// `zgrab2 multiple`: one JSON line per target IP, with Data keyed by
// whatever section/module name the ini config assigned.
type grabRecord struct {
	IP     string                  `json:"ip,omitempty"`
	Port   uint                    `json:"port,omitempty"`
	Domain string                  `json:"domain,omitempty"`
	Data   map[string]scanResponse `json:"data,omitempty"`
	Error  string                  `json:"error,omitempty"`
}
