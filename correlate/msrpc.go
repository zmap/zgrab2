package correlate

import (
	"encoding/json"
	"fmt"

	"github.com/zmap/zgrab2/lib/attribution"
	"github.com/zmap/zgrab2/modules/msrpc"
)

func extractMSRPC(raw json.RawMessage) (*msrpc.Results, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var res msrpc.Results
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("decoding msrpc result: %w", err)
	}
	return &res, nil
}

// msrpcSignalFrom grades a DCE/RPC Bind response on the RPC Endpoint Mapper
// interface. This is a Windows-convention-specific signal (EPM at port 135
// is overwhelmingly a Windows pattern in practice), but not exclusively so,
// so standalone confidence is medium -- corroboration from another protocol
// raises it (see combineOSIdentification).
func msrpcSignalFrom(res *msrpc.Results) protocolSignal {
	if res == nil {
		return protocolSignal{}
	}
	return protocolSignal{
		windowsFamilyConfidence: attribution.ConfidenceMedium,
		evidence: []Evidence{{
			Source:     "rpc",
			Signal:     "microsoft_rpc_endpoint_mapper_" + res.PDUType,
			Confidence: attribution.ConfidenceMedium,
		}},
	}
}
