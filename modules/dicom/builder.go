package dicom

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

var ErrAssociationReject = errors.New("association rejected")

// TODO: idially we would just wrap and unwrap messages from the packet structure instead
// of storing lengths everywere. I leave this for future rewrites. The same goes for types,
// just create an interface with bytes and wrap functions.
type PDUType uint8

const (
	ASSOC_RQ     PDUType = 1
	ASSOC_ACCEPT PDUType = 2
	ASSOC_REJECT PDUType = 3
	DATA         PDUType = 4
)

type PDUMsg interface {
	bytes() []byte
}

type PDVCommand struct {
	GroupTag   uint16
	ElementTag uint16
	Length     uint32 // we only keep this value for sanity
	Value      []byte
}

func newPDVCommand(group, tag uint16, value []byte) *PDVCommand {
	// value is always an even number of bytes
	if len(value)%2 != 0 {
		value = append(value, 0x00)
	}

	return &PDVCommand{group, tag, uint32(len(value)), value}
}

func (cmd *PDVCommand) bytes() []byte {
	buf := make([]byte, 0, cmd.Length+8)
	buf = binary.LittleEndian.AppendUint16(buf, cmd.GroupTag)
	buf = binary.LittleEndian.AppendUint16(buf, cmd.ElementTag)
	buf = binary.LittleEndian.AppendUint32(buf, cmd.Length)
	buf = append(buf, cmd.Value...)
	return buf
}

type PDV struct {
	Legnth   uint32 // we only keep this value for sanity
	Context  uint8
	Flags    uint8
	Commands []*PDVCommand
	// NOTE: we dont care about the dataset!
}

func (p *PDV) bytes() []byte {
	buf := make([]byte, 0, p.Legnth)
	buf = binary.BigEndian.AppendUint32(buf, p.Legnth)
	buf = append(buf, p.Context, p.Flags)

	for _, cmd := range p.Commands {
		buf = append(buf, cmd.bytes()...)
	}

	return buf
}

type PDUHeader struct {
	PDUType PDUType
	Length  uint32 // we only keep this value for sanity
}

func (h *PDUHeader) bytes() []byte {
	header := make([]byte, 0)
	header = append(header, uint8(h.PDUType), 0x00)
	header = binary.BigEndian.AppendUint32(header, h.Length)
	return header
}

type PDU struct {
	Header *PDUHeader
	Msg    PDUMsg
}

func newPDU(t PDUType) *PDU {
	return &PDU{
		Header: &PDUHeader{
			PDUType: t,
		},
	}
}

func (p *PDU) withMessage(msg PDUMsg) *PDU {
	p.Header.Length = uint32(len(msg.bytes()))
	p.Msg = msg
	return p
}

func (pdu *PDU) readHeader(data io.Reader) error {
	buf := make([]byte, 6)
	if _, err := data.Read(buf); err != nil {
		return fmt.Errorf("failed to read header bytes: %w", err)
	}

	pdu.Header = &PDUHeader{
		PDUType: PDUType(buf[0]),
		Length:  binary.BigEndian.Uint32(buf[2:6]),
	}
	return nil
}

func (pdu *PDU) parseAssociationMsg(data []byte) (*AAssociate, error) {
	if l := len(data); l < 37 {
		return nil, fmt.Errorf("association message too short: expected at least 37 bytes, but received %d", l)
	}

	trimString := func(b []byte) string {
		return strings.TrimRight(string(b), " \x00")
	}

	assoc := &AAssociate{
		ProtocolVersion: binary.BigEndian.Uint16(data[0:2]),
		CalledAETitle:   trimString(data[4:20]),
		CallingAETitle:  trimString(data[20:37]),
	}

	// 36 from the calling AE title + 32 reserved bytes
	i := 68
	for i+4 <= len(data) {
		iType := data[i]
		iLength := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		iValue := data[i+4 : i+4+int(iLength)]

		switch iType {
		// Application Context
		case 0x10:
			assoc.ApplicationContext = string(iValue)

		// Presentation context
		case 0x20, 0x21:
			buf := bytes.NewReader(iValue[4:])
			ps := newPresentationContext(iValue[0], iValue[2])

			for buf.Len() > 0 {
				item, err := parseItem(buf)
				if err != nil {
					return nil, fmt.Errorf("fialed to parse Presentation Context Item %w", err)
				}
				ps.Items = append(ps.Items, item)
			}
			assoc.PresentationContext = ps

		// User Info
		case 0x50:
			buf := bytes.NewReader(iValue)
			uInfo := newUserInfo()

			for buf.Len() > 0 {
				item, err := parseItem(buf)
				if err != nil {
					return nil, fmt.Errorf("failed to parse User Info Item: %w", err)
				}
				uInfo.Items = append(uInfo.Items, item)
			}
			assoc.UserInfo = uInfo
		}
		// sum 4 (iType + len) to the Item length
		i += 4 + iLength
	}

	return assoc, nil
}

func (pdu *PDU) parseDataMsg(data []byte) (*PDV, error) {
	l := binary.BigEndian.Uint32(data[:4])
	ctx := data[4]
	flags := data[5]
	cmds := data[6 : 6+l-2]

	pdv := &PDV{
		Legnth:   uint32(len(cmds) + 2), // cms + ctx & flags
		Context:  ctx,
		Flags:    flags,
		Commands: []*PDVCommand{},
	}

	i := 0
	for i+8 <= len(cmds) {
		tagGroup := binary.LittleEndian.Uint16(cmds[i : i+2])
		tagElem := binary.LittleEndian.Uint16(cmds[i+2 : i+4])
		length := binary.LittleEndian.Uint32(cmds[i+4 : i+8])

		if i+8+int(length) > len(cmds) {
			return nil, fmt.Errorf("element length exceeds buffer at offset %d", i)
		}
		value := cmds[i+8 : i+8+int(length)]

		pdv.Commands = append(pdv.Commands, newPDVCommand(tagGroup, tagElem, value))
		i += 8 + int(length)
	}

	return pdv, nil
}

func (pdu *PDU) readMessage(data io.Reader) error {
	msgBuff := make([]byte, pdu.Header.Length)
	if _, err := data.Read(msgBuff); err != nil {
		return fmt.Errorf("failed to read message bytes: %w", err)
	}

	switch pdu.Header.PDUType {
	case ASSOC_REJECT:
		return ErrAssociationReject
	case ASSOC_RQ, ASSOC_ACCEPT:
		msg, err := pdu.parseAssociationMsg(msgBuff)
		if err != nil {
			return fmt.Errorf("failed to parse association message: %w", err)
		}
		pdu.Msg = msg
	case DATA:
		msg, err := pdu.parseDataMsg(msgBuff)
		if err != nil {
			return fmt.Errorf("failed to parse association message: %w", err)
		}
		pdu.Msg = msg
	default:
		return fmt.Errorf("unable to parse PDU type %x", pdu.Header.PDUType)
	}
	return nil
}

func parsePDU(data io.Reader) (*PDU, error) {
	pdu := &PDU{}

	if err := pdu.readHeader(data); err != nil {
		return nil, fmt.Errorf("failed to parse PDU header: %w", err)
	}

	if err := pdu.readMessage(data); err != nil {
		return nil, fmt.Errorf("failed to parse PDU content: %w", err)
	}

	return pdu, nil
}

func (pdu PDU) bytes() []byte {
	b := make([]byte, 0)
	b = append(b, pdu.Header.bytes()...)
	b = append(b, pdu.Msg.bytes()...)
	return b
}

type TransferSyntax struct {
	IType uint8
	Value string
}

type PresentationContext struct {
	Type      uint8
	ContextID uint8
	Result    uint8
	Items     []*Item
}

func newPresentationContext(id, result uint8) *PresentationContext {
	return &PresentationContext{
		Type:      0x20,
		ContextID: id,
		Result:    result,
		Items:     []*Item{},
	}
}

func (p *PresentationContext) bytes() []byte {
	tssBuf := make([]byte, 0)
	for _, ts := range p.Items {
		tssBuf = append(tssBuf, ts.bytes()...)
	}

	buf := make([]byte, 0, 4+len(tssBuf))
	buf = append(buf, p.Type, 0x00)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(tssBuf))+4)
	buf = append(buf,
		p.ContextID, 0x00,
		p.Result, 0x00,
	)
	buf = append(buf, tssBuf...)
	return buf
}

type Item struct {
	Type   uint8
	Length uint16
	Value  []byte
}

func parseItem(data io.Reader) (*Item, error) {
	i := Item{}

	bType := make([]byte, 2)
	if _, err := data.Read(bType); err != nil {
		return nil, fmt.Errorf("failed to read Item Type: %w", err)
	}
	i.Type = uint8(bType[0])

	bLength := make([]byte, 2)
	if _, err := data.Read(bLength); err != nil {
		return nil, fmt.Errorf("failed to read Item Length: %w", err)
	}
	i.Length = binary.BigEndian.Uint16(bLength)

	bValue := make([]byte, i.Length)
	if _, err := data.Read(bValue); err != nil {
		return nil, fmt.Errorf("failed to read Item Value: %w", err)
	}
	i.Value = bValue

	return &i, nil
}

func newItem(t uint8, value []byte) *Item {
	return &Item{
		Type:   t,
		Length: uint16(len(value)),
		Value:  value,
	}
}

func (i *Item) bytes() []byte {
	buf := []byte{i.Type, 0x00}
	buf = binary.BigEndian.AppendUint16(buf, i.Length)
	buf = append(buf, i.Value...)
	return buf
}

type UserInfo struct {
	Type  uint8
	Items []*Item
}

func newUserInfo() *UserInfo {
	return &UserInfo{
		Type: 0x50, // Item Type = 0x50 (User Info)
	}
}

func (u *UserInfo) bytes() []byte {
	itBuf := make([]byte, 0)
	for _, it := range u.Items {
		itBuf = append(itBuf, it.bytes()...)
	}

	buf := []byte{u.Type, 0x00}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(itBuf)))
	buf = append(buf, itBuf...)

	return buf
}

type AAssociate struct {
	ProtocolVersion     uint16
	CallingAETitle      string
	CalledAETitle       string
	ApplicationContext  string
	PresentationContext *PresentationContext
	UserInfo            *UserInfo
}

func makeAAssociateRQ(msgID uint8, callingAETitle string, calledAETitle string) *AAssociate {
	uInfo := newUserInfo()
	uInfo.Items = []*Item{
		newItem(0x51, []byte{0x00, 0x00, 0x40, 0x00}),
		newItem(0x52, []byte("1.2.276.0.7230010.3.0.3.6.6")),
		newItem(0x55, []byte("ZGRAB2")),
	}

	return &AAssociate{
		ProtocolVersion:     1,
		CallingAETitle:      callingAETitle,
		CalledAETitle:       calledAETitle,
		ApplicationContext:  "1.2.840.10008.3.1.1.1",
		PresentationContext: newPresentationContext(msgID, 0xff),
		UserInfo:            uInfo,
	}
}

func (a *AAssociate) addTransferSyntax(iType uint8, value string) *AAssociate {
	a.PresentationContext.Items = append(a.PresentationContext.Items, newItem(iType, []byte(value)))
	return a
}

func (a *AAssociate) header() []byte {
	buf := make([]byte, 0, 68)
	buf = binary.BigEndian.AppendUint16(buf, a.ProtocolVersion)
	buf = append(buf, 0x00, 0x00)

	calledAETitle := [16]byte{}
	callingAETitle := [16]byte{}
	copy(calledAETitle[:], []byte(a.CalledAETitle))
	copy(callingAETitle[:], []byte(a.CallingAETitle))

	buf = append(buf, calledAETitle[:]...)
	buf = append(buf, callingAETitle[:]...)
	buf = append(buf, make([]byte, 32)...) // Reserved

	return buf
}

func (a *AAssociate) applicationContext() []byte {
	buf := make([]byte, 0, len(a.ApplicationContext)+4)
	buf = append(buf, 0x10, 0x00)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.ApplicationContext)))
	buf = append(buf, []byte(a.ApplicationContext)...)
	return buf
}

func (a *AAssociate) bytes() []byte {
	msg := make([]byte, 0)
	msg = append(msg, a.header()...)
	msg = append(msg, a.applicationContext()...)
	msg = append(msg, a.PresentationContext.bytes()...)
	msg = append(msg, a.UserInfo.bytes()...)
	return msg
}

func makeCEchoRQ(msgID uint16) *PDV {
	commands := []*PDVCommand{}
	commands = append(
		commands,
		newPDVCommand(0, 0x0002, []byte("1.2.840.10008.1.1")),
		newPDVCommand(0, 0x0100, []byte{0x30, 0x00}),
		newPDVCommand(0, 0x0110, []byte{byte(msgID) >> 0, byte(msgID) >> 1}),
		newPDVCommand(0, 0x0800, []byte{0x01, 0x01}),
	)

	g := make([]byte, 0)
	for _, cmd := range commands {
		g = append(g, cmd.bytes()...)
	}

	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(g)))
	commands = append([]*PDVCommand{newPDVCommand(0, 0, b)}, commands...)

	return &PDV{
		Legnth:   70,
		Context:  0x01,
		Flags:    0x03,
		Commands: commands,
	}
}
