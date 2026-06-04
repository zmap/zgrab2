package checkpoint

import "testing"

func FuzzDecodeTopologyResponse(f *testing.F) {
	// Valid response: 4-byte header + "CN=fw1.example.com,O=example.com" + 8-byte trailer
	f.Add([]byte{0x00, 0x00, 0x00, 0x28, 'C', 'N', '=', 'f', 'w', '1', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', ',', 'O', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte("\u0000\u0000\u00008CN=IL-CH3-FW04,O=MN-MSP-EMC.OldRepublicTitle.com.4yyzo3\u0000\u0000\u0000\u0000\n\u0000\u0000\u0000\u0005none\u0000\u0000\u0000\u0000\fsslca_clear\u0000\u0000\u0000\u0000\u0006sslca\u0000\u0000\u0000\u0000\u000bsslca_comp\u0000\u0000\u0000\u0000\nsslca_rc4\u0000\u0000\u0000\u0000\u000fsslca_rc4_comp\u0000\u0000\u0000\u0000\u000basym_sslca\u0000\u0000\u0000\u0000\u0010asym_sslca_comp\u0000\u0000\u0000\u0000\u000fasym_sslca_rc4\u0000\u0000\u0000\u0000\u0014asym_sslca_rc4_comp\u0000"))
	f.Add([]byte("\u0000\u0000\u00008CN=IL-CH3-FW04,O=MN\u0000\u0000\u0000\u0000\n\u0000\u0000\u0000\u0005none\u0000\u0000\u0000\u0000\fsslca_clear\u0000\u0000\u0000\u0000\u0006sslca\u0000\u0000\u0000\u0000\u000bsslca_comp\u0000\u0000\u0000\u0000\nsslca_rc4\u0000\u0000\u0000\u0000\u000fsslca_rc4_comp\u0000\u0000\u0000\u0000\u000basym_sslca\u0000\u0000\u0000\u0000\u0010asym_sslca_comp\u0000\u0000\u0000\u0000\u000fasym_sslca_rc4\u0000\u0000\u0000\u0000\u0014asym_sslca_rc4_comp\u0000"))
	f.Add([]byte("\u0000\u0000\u00008CN=IL-CH3-FW04,O=MN\u0000\u0005none\u0000\u0000\u0000\u0000"))
	f.Add(make([]byte, 13))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		results := &ScanResults{}
		_ = decodeTopologyResponse(string(data), results, false)
	})
}

func FuzzDecodeCheckpointProbeResponse(f *testing.F) {
	f.Add(expectedCheckpointResponseProbeOne) // Valid response
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{})
	f.Add(make([]byte, 13))
	f.Fuzz(func(t *testing.T, data []byte) {
		results := &ScanResults{}
		_ = decodeCheckpointProbeResponse(data, results)
	})
}
