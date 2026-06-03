#!/usr/bin/env bash
set -euo pipefail

PROTO="${1:-}"

if [ -z "$PROTO" ]; then
    echo "Usage: make scaffold-new-module PROTO=<protocol>" >&2
    exit 1
fi

SCANNER_DIR="modules/$PROTO"
SCANNER_FILE="$SCANNER_DIR/scanner.go"
WRAPPER_FILE="modules/$PROTO.go"

if [ -d "$SCANNER_DIR" ]; then
    echo "Error: $SCANNER_DIR already exists" >&2
    exit 1
fi
if [ -f "$WRAPPER_FILE" ]; then
    echo "Error: $WRAPPER_FILE already exists" >&2
    exit 1
fi

mkdir -p "$SCANNER_DIR"

cat > "$SCANNER_FILE" << EOF
package $PROTO

import (
	"context"

	"github.com/zmap/zgrab2"
)

// TODO: Add flag fields specific to this protocol.
type Flags struct {
	zgrab2.BaseFlags \`group:"Basic Options"\`
	// TODO: add TLS flags if your protocol requires
	// zgrab2.TLSFlags \`group:"TLS Options"\`
}

// TODO: Return an error if flag combinations are invalid.
// Only required if you have flags to validate. Modules like HTTP have custom flag validation logic, so they'll need to implement this.
// If you don't, you can omit it.
func (f Flags) Validate(_ []string) error {
	return nil
}

// TODO: Add result fields collected during the scan.
type Results struct {
    // TODO: only required for modules with TLS
	  // TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// TODO: Add any per-scanner state your Scan() needs between calls.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// TODO: Update the short description, long description, and default port.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"$PROTO",
		"TODO: one-line description shown in \`zgrab2 --help\`",
		"TODO: full description shown in \`zgrab2 $PROTO --help\`",
		0, // TODO: set the well-known port for this protocol
	)
}

// TODO: Cast flags, call SetBaseFlags, and configure DialerGroupConfig.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	s.SetBaseFlags(&f.BaseFlags)
	s.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP, // TODO: or TransportUDP
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// TODO: Implement the scan - connect, perform the protocol handshake, populate Results.
func (s *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	// TODO: use dialGroup.Dial or dialGroup.L4Dialer to open a connection to target,
	// then implement the protocol exchange and return the results.
	return zgrab2.SCAN_SUCCESS, &Results{}, nil
}
EOF

cat > "$WRAPPER_FILE" << EOF
package modules

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/$PROTO"
)

func init() {
	zgrab2.RegisterModule($PROTO.NewModule())
}
EOF

echo "Scaffolded new module: $SCANNER_FILE and $WRAPPER_FILE"
echo ""
echo "Next steps:"
echo "  1. Fill in the TODOs in $SCANNER_FILE"
echo "  2. Add an entry to bin/default_modules.go if you want it in the default module set"
echo "  3. Add integration tests under integration_tests/$PROTO/"
