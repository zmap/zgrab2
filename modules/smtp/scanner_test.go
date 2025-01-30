package smtp

import (
	"github.com/zmap/zgrab2"
	"testing"
)

func TestVerifySMTPContents(t *testing.T) {
	type Test struct {
		Banner         string
		ExpectedStatus zgrab2.ScanStatus
		ExpectedCode   int
	}
	testTable := map[string]Test{
		"success with code": {
			Banner: `220-some.host.com ESMTP Exim 4.93 #2 Thu, 04 Feb 2021 13:34:12 -0500 
220-We do not authorize the use of this system to transport unsolicited, 
220 and/or bulk e-mail.`,
			ExpectedStatus: zgrab2.SCAN_SUCCESS,
			ExpectedCode:   0,
		},
		"success without code": {
			Banner: `ESMTP Exim 4.93 #2 Thu, 04 Feb 2021 13:34:12 -0500 
220-We do not authorize the use of this system to transport unsolicited, 
220 and/or bulk e-mail.`,
			ExpectedStatus: zgrab2.SCAN_SUCCESS,
			ExpectedCode:   0,
		},
		"invalid protocol": {
			Banner:         "gibberish that doesnt match expected response",
			ExpectedStatus: zgrab2.SCAN_PROTOCOL_ERROR,
			ExpectedCode:   0,
		},
		"error response": {
			Banner:         "500-some.host.com ESMTP something went horribly wrong.",
			ExpectedStatus: zgrab2.SCAN_APPLICATION_ERROR,
			ExpectedCode:   500,
		},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			status, code := VerifySMTPContents(test.Banner)
			if status != test.ExpectedStatus {
				t.Errorf("recieved unexpected status: %s, wanted: %s", status, test.ExpectedStatus)
			}
			if code != test.ExpectedCode {
				t.Errorf("recieved unexpected code: %d, wanted: %d", code, test.ExpectedCode)
			}
		})
	}

}
