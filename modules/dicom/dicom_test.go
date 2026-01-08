package dicom

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

type dicomTester struct {
	target         zgrab2.ScanTarget
	expectedStatus zgrab2.ScanStatus
}

func (t *dicomTester) getScanner() (*Scanner, error) {
	var module Module
	flags := module.NewFlags().(*Flags)

	flags.UseTLS = false
	flags.CalledAETitles = "ORTHANC,DCM4CHEE"
	flags.CallingAETitle = "ZGRAB-TEST"

	scanner := module.NewScanner()
	if err := scanner.Init(flags); err != nil {
		return nil, err
	}

	return scanner.(*Scanner), nil
}

func (t *dicomTester) runTest(test *testing.T, name string) {
	scanner, err := t.getScanner()
	if err != nil {
		test.Fatalf("[%s] Unexpected error: %v", name, err)
	}

	baseFlags := &zgrab2.BaseFlags{
		Port:           t.target.Port,
		ConnectTimeout: time.Second * 20,
		TargetTimeout:  time.Second * 20,
	}

	dialerGroupConfig := zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       baseFlags,
		TLSEnabled:                      scanner.config.UseTLS,
	}

	dialerGroup, err := dialerGroupConfig.GetDefaultDialerGroupFromConfig()
	if err != nil {
		test.Fatalf("Error getting default dialer group: %v", err)
	}

	status, ret, err := scanner.Scan(context.Background(), dialerGroup, &t.target)
	if status != t.expectedStatus {
		test.Errorf("[%s] Wrong status: expected %s, got %s", name, t.expectedStatus, status)
	}

	if err != nil {
		test.Errorf("[%s] Unexpected error: %v", name, err)
	}

	if ret == nil {
		test.Errorf("[%s] Got empty response", name)
	}
}

var tests = map[string]*dicomTester{
	"success": {
		target: zgrab2.ScanTarget{
			Domain: "https://www.dicomserver.co.uk/",
			Port:   104,
		},
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
}

func TestDICOM(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}

type craftAndParse struct{}

func (t *craftAndParse) runTest(test *testing.T, name string) {
	assoc := makeAAssociateRQ(1, "testcalling", "testcaller", "1.2.3.4.5", "test_1")
	assoc.addTransferSyntax(0x30, "1.2.840.10008.1.1")

	assocPDU := newPDU(PDUType(1)).withMessage(assoc)

	bAssocRQ := assocPDU.bytes()
	pAssoc, err := parsePDU(bytes.NewReader(bAssocRQ))
	if err != nil {
		test.Errorf("[%s] Failed to parse PDU", name)
	}

	if !reflect.DeepEqual(pAssoc.bytes(), bAssocRQ) {
		test.Errorf("[%s] Mismatched Association PDUs: got %v, expected %v", name, pAssoc, assocPDU)
	}

	echo := makeCEchoRQ(1)
	echoPDU := newPDU(PDUType(4)).withMessage(echo)

	bEchoRQ := echoPDU.bytes()
	pEcho, err := parsePDU(bytes.NewReader(bEchoRQ))
	if err != nil {
		test.Errorf("[%s] Failed to parse Echo PDU", name)
	}

	if !reflect.DeepEqual(pEcho.bytes(), bEchoRQ) {
		test.Errorf("[%s] Mismatched Echo PDUs: got %v, expected %v", name, pEcho, echoPDU)
	}
}

var tests2 = map[string]*craftAndParse{
	"success": {},
}

func TestDICOMCraftAndParse(t *testing.T) {
	for tname, cfg := range tests2 {
		cfg.runTest(t, tname)
	}
}
