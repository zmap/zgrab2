package siemens

import (
	"encoding/binary"
	"errors"
)

// TPKTPacket is defined in RFC 1006
type TPKTPacket struct {
	// Data is the packet's content
	Data []byte
}

const tpktLength = 4 // 4 bytes (excluding Data slice)

// Marshal encodes a TPKTPacket to binary.
func (tpktPacket *TPKTPacket) Marshal() ([]byte, error) {

	totalLength := len(tpktPacket.Data) + tpktLength
	bytes := make([]byte, 0, totalLength)

	bytes = append(bytes, byte(3)) // version
	bytes = append(bytes, byte(0)) // reserved
	uint16BytesHolder := make([]byte, 2)
	binary.BigEndian.PutUint16(uint16BytesHolder, uint16(totalLength))
	bytes = append(bytes, uint16BytesHolder...)
	bytes = append(bytes, tpktPacket.Data...)

	return bytes, nil
}

// Unmarshal decodes a TPKTPacket from binary.
func (tpktPacket *TPKTPacket) Unmarshal(bytes []byte) error {

	if len(bytes) < tpktLength {
		return errS7PacketTooShort
	}

	tpktPacket.Data = bytes[tpktLength:]

	return nil
}

// COTPConnectionPacket is defined in RFC 892.
type COTPConnectionPacket struct {
	// DestinationRef is the DST-REF TPDU field
	DestinationRef uint16

	// SourceRef is the SCE-REF TPDU field
	SourceRef uint16

	// DestinationTSAP is the destination transport service access point.
	DestinationTSAP uint16

	// SourceTSAP is the source transport service access point.
	SourceTSAP uint16

	// TPDUSize is the size (in bytes) of the TPDU
	TPDUSize byte
}

const cotpConnRequestLength = 18

// Marshal encodes a COTPConnectionPacket to binary.
func (cotpConnPacket *COTPConnectionPacket) Marshal() ([]byte, error) {
	bytes := make([]byte, 0, cotpConnRequestLength)
	uint16BytesHolder := make([]byte, 2)

	bytes = append(bytes, byte(cotpConnRequestLength-1)) // length of packet (excluding 1-byte length header)
	bytes = append(bytes, byte(0xe0))                    // connection request code
	binary.BigEndian.PutUint16(uint16BytesHolder, cotpConnPacket.DestinationRef)
	bytes = append(bytes, uint16BytesHolder...)
	binary.BigEndian.PutUint16(uint16BytesHolder, cotpConnPacket.SourceRef)
	bytes = append(bytes, uint16BytesHolder...)
	bytes = append(bytes, byte(0))    // class 0 transport protocol with no flags
	bytes = append(bytes, byte(0xc1)) // code for identifier of the calling TSAP field
	bytes = append(bytes, byte(2))    // byte-length of subsequent field SourceTSAP
	binary.BigEndian.PutUint16(uint16BytesHolder, cotpConnPacket.SourceTSAP)
	bytes = append(bytes, uint16BytesHolder...)
	bytes = append(bytes, byte(0xc2)) // code fo identifier of the called TSAP field
	bytes = append(bytes, byte(2))    // byte-length of subsequent field DestinationTSAP
	binary.BigEndian.PutUint16(uint16BytesHolder, cotpConnPacket.DestinationTSAP)
	bytes = append(bytes, uint16BytesHolder...)
	bytes = append(bytes, byte(0xc0)) // code for proposed maximum TPDU size field
	bytes = append(bytes, byte(1))    // byte-length of subsequent field
	bytes = append(bytes, cotpConnPacket.TPDUSize)

	return bytes, nil
}

// Unmarshal decodes a COTPConnectionPacket from binary that must be a connection confirmation.
func (cotpConnPacket *COTPConnectionPacket) Unmarshal(bytes []byte) error {

	if bytes == nil || len(bytes) < 2 {
		return errInvalidPacket
	}

	if sizeByte := bytes[0]; int(sizeByte)+1 != len(bytes) {
		return errS7PacketTooShort
	}

	if pduType := bytes[1]; pduType != 0xd0 {
		return errors.New("Not a connection confirmation packet")
	}

	// TODO: implement these fields with proper bounds checking
	//	cotpConnPacket.DestinationRef = binary.BigEndian.Uint16(bytes[2:4])
	//	cotpConnPacket.SourceRef = binary.BigEndian.Uint16(bytes[4:6])
	//	cotpConnPacket.DestinationTSAP
	//	cotpConnPacket.SourceTSAP
	//	cotpConnPacket.TPDUSize

	return nil
}

// COTPDataPacket wraps the state / interface for a COTP data packet.
type COTPDataPacket struct {
	Data []byte
}

const cotpDataPacketHeaderLength = 2

// Marshal encodes a COTPDataPacket to binary.
func (cotpDataPacket *COTPDataPacket) Marshal() ([]byte, error) {
	bytes := make([]byte, 0, cotpDataPacketHeaderLength+len(cotpDataPacket.Data))

	bytes = append(bytes, byte(2))    // data header length
	bytes = append(bytes, byte(0xf0)) // code for data packet
	bytes = append(bytes, byte(0x80)) // code for data packet
	bytes = append(bytes, cotpDataPacket.Data...)

	return bytes, nil
}

// Unmarshal decodes a COTPDataPacket from binary.
func (cotpDataPacket *COTPDataPacket) Unmarshal(bytes []byte) error {

	if bytes == nil || len(bytes) < 1 {
		return errInvalidPacket
	}

	headerSize := bytes[0]

	if int(headerSize+1) > len(bytes) {
		return errInvalidPacket
	}

	cotpDataPacket.Data = bytes[headerSize+1:]

	return nil
}

// S7Packet represents an S7 packet.
type S7Packet struct {
	PDUType    byte
	RequestId  uint16
	Parameters []byte
	Data       []byte
	Error      uint16
}

const (
	S7_PROTOCOL_ID                  = byte(0x32)
	S7_REQUEST_ID                   = uint16(0)
	S7_REQUEST                      = byte(0x01)
	S7_REQUEST_USER_DATA            = byte(0x07)
	S7_ACKNOWLEDGEMENT              = byte(0x02)
	S7_RESPONSE                     = byte(0x03)
	S7_SZL_REQUEST                  = byte(0x04)
	S7_SZL_FUNCTIONS                = byte(0x04)
	S7_SZL_READ                     = byte(0x01)
	S7_SZL_MODULE_IDENTIFICATION    = uint16(0x11)
	S7_SZL_COMPONENT_IDENTIFICATION = uint16(0x1c)
	S7_DATA_BYTE_OFFSET             = 12 // offset for real data
)

const s7PacketHeaderLength = 3

// Marshal encodes a S7Packet to binary.
func (s7Packet *S7Packet) Marshal() ([]byte, error) {

	if s7Packet.PDUType != S7_REQUEST && s7Packet.PDUType != S7_REQUEST_USER_DATA {
		return nil, errors.New("Invalid PDU request type")
	}

	bytes := make([]byte, 0, s7PacketHeaderLength+len(s7Packet.Data))
	uint16BytesHolder := make([]byte, 2)

	bytes = append(bytes, S7_PROTOCOL_ID) // s7 protocol id
	bytes = append(bytes, s7Packet.PDUType)
	binary.BigEndian.PutUint16(uint16BytesHolder, 0)
	bytes = append(bytes, uint16BytesHolder...) // reserved
	binary.BigEndian.PutUint16(uint16BytesHolder, s7Packet.RequestId)
	bytes = append(bytes, uint16BytesHolder...)
	binary.BigEndian.PutUint16(uint16BytesHolder, uint16(len(s7Packet.Parameters)))
	bytes = append(bytes, uint16BytesHolder...)
	binary.BigEndian.PutUint16(uint16BytesHolder, uint16(len(s7Packet.Data)))
	bytes = append(bytes, uint16BytesHolder...)
	bytes = append(bytes, s7Packet.Parameters...)
	bytes = append(bytes, s7Packet.Data...)

	return bytes, nil
}

// Unmarshal decodes a S7Packet from binary.
func (s7Packet *S7Packet) Unmarshal(bytes []byte) (err error) {
	if bytes == nil || len(bytes) < 1 {
		return errInvalidPacket
	}

	if protocolId := bytes[0]; protocolId != S7_PROTOCOL_ID {
		return errNotS7
	}

	var headerSize int
	pduType := bytes[1]

	if pduType == S7_ACKNOWLEDGEMENT || pduType == S7_RESPONSE {
		headerSize = 12
		s7Packet.Error = binary.BigEndian.Uint16(bytes[10:12])
	} else if pduType == S7_REQUEST || pduType == S7_REQUEST_USER_DATA {
		headerSize = 10
	} else {
		return errors.New("Unknown PDU type " + string(pduType))
	}

	s7Packet.PDUType = pduType
	s7Packet.RequestId = binary.BigEndian.Uint16(bytes[4:6])
	paramLength := int(binary.BigEndian.Uint16(bytes[6:8]))
	dataLength := int(binary.BigEndian.Uint16(bytes[8:10]))

	if paramLength < 0 || dataLength < 0 || headerSize+paramLength+dataLength > len(bytes) {
		return errInvalidPacket
	}

	s7Packet.Parameters = bytes[headerSize : headerSize+paramLength]
	s7Packet.Data = bytes[headerSize+paramLength : headerSize+paramLength+dataLength]

	return nil
}
