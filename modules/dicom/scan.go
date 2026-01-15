package dicom

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/zmap/zgrab2"
)

type ScanResult struct {
	Scheme      string         `json:"scheme"`
	Association *PDU           `json:"association,omitempty"`
	Echo        *PDU           `json:"echo,omitempty"`
	TLSLog      *zgrab2.TLSLog `json:"tls,omitempty"`
}

type scan struct {
	ctx       context.Context
	dialGroup *zgrab2.DialerGroup

	target  *zgrab2.ScanTarget
	scanner *Scanner
	scheme  string
	result  ScanResult

	calledAETitle string
	msgID         uint8
}

func (s *scan) connect() (net.Conn, *zgrab2.ScanError) {
	addr := net.JoinHostPort(s.target.Host(), strconv.Itoa(int(s.target.Port)))
	conn, err := s.dialGroup.L4Dialer(s.target)(s.ctx, "tcp", addr)
	if err != nil {
		return nil, zgrab2.NewScanError(zgrab2.TryGetScanStatus(err), fmt.Errorf("error opening connection to target %v: %w", addr, err))
	}

	if s.scheme == "tls" {
		w := s.dialGroup.TLSWrapper
		if w == nil {
			return nil, zgrab2.NewScanError(zgrab2.SCAN_INVALID_INPUTS, errors.New("missing TLS wrapper"))
		}
		conn, err = w(s.ctx, s.target, conn)
		if err != nil {
			return nil, zgrab2.DetectScanError(err)
		}
	}

	return conn, nil
}

func (s *scan) sendAAssociateRQ(conn net.Conn, calledAE, callingAE, impUID, impVName string) error {
	assoc := makeAAssociateRQ(s.msgID, callingAE, calledAE, impUID, impVName)
	assoc.addTransferSyntax(0x30, "1.2.840.10008.1.1") // abstract
	assoc.addTransferSyntax(0x40, "1.2.840.10008.1.2") // default for DICOM

	pdu := newPDU(PDUType(1)).withMessage(assoc)

	_, err := conn.Write(pdu.bytes())
	if err != nil {
		return fmt.Errorf("failed to send Association request: %w", err)
	}
	return nil
}

func (s *scan) associate(conn net.Conn) *zgrab2.ScanError {
	if err := s.sendAAssociateRQ(
		conn,
		s.calledAETitle,
		s.scanner.config.CallingAETitle,
		s.scanner.config.ImplementationClassUID,
		s.scanner.config.ImplementationVersionName,
	); err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	pdu, err := parsePDU(conn)
	s.result.Association = pdu
	if err != nil {
		errft := fmt.Errorf("failed to parse association response: %w", err)
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, errft)
	}
	return nil
}

func (s *scan) sendCEchoRQ(conn net.Conn) error {
	echo := makeCEchoRQ(uint16(s.msgID))
	pdu := newPDU(PDUType(4)).withMessage(echo)

	if _, err := conn.Write(pdu.bytes()); err != nil {
		return fmt.Errorf("failed to send Echo request: %w", err)
	}
	return nil
}

func (s *scan) echo(conn net.Conn) *zgrab2.ScanError {
	if err := s.sendCEchoRQ(conn); err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	rsp, err := parsePDU(conn)
	s.result.Echo = rsp
	if err != nil {
		fmterr := fmt.Errorf("failed to parse Echo response: %w", err)
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, fmterr)
	}
	return nil
}

func (s *scan) Grab(calledAETitle string) *zgrab2.ScanError {
	conn, err := s.connect()
	if err != nil {
		return err
	}
	defer func() {
		// Check if we have a TLS conn and grab the log
		if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok {
			s.result.TLSLog = tlsConn.GetLog()
		}
		// cleanup conn
		zgrab2.CloseConnAndHandleError(conn)
	}()

	s.calledAETitle = calledAETitle
	for _, callback := range []func(net.Conn) *zgrab2.ScanError{s.associate, s.echo} {
		if err := callback(conn); err != nil {
			return err
		}
	}
	return nil
}

type ScanBuilder struct {
	scanner *Scanner
}

func NewScanBuilder(scn *Scanner) *ScanBuilder {
	return &ScanBuilder{scn}
}

func (b *ScanBuilder) Build(ctx context.Context, dialGroup *zgrab2.DialerGroup, t *zgrab2.ScanTarget, scheme string) *scan {
	return &scan{
		ctx:       ctx,
		dialGroup: dialGroup,
		scanner:   b.scanner,
		target:    t,
		scheme:    scheme,
		result: ScanResult{
			Scheme: scheme,
		},
		msgID: 1,
	}
}
