package siemens

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/zmap/zgrab2"
)

const s7ModuleIdRecordSize = 28
const (
	s7ModuleIdModuleIndex   = 0x1
	s7ModuleIdHardwareIndex = 0x6
	s7ModuleIdFirmwareIndex = 0x7
)

const uint16Size = 2

// ReconnectFunction is used to re-connect to the target to re-try the scan with a different TSAP destination.
type ReconnectFunction func() (net.Conn, error)

// GetS7Banner scans the target for S7 information, reconnecting if necessary.
func GetS7Banner(logStruct *S7Log, connection net.Conn, reconnect ReconnectFunction) (err error) {
	// Attempt connection
	var connPacketBytes, connResponseBytes []byte
	connPacketBytes, err = makeCOTPConnectionPacketBytes(uint16(0x102), uint16(0x100))
	if err != nil {
		return err
	}
	connResponseBytes, err = sendRequestReadResponse(connection, connPacketBytes)
	if connResponseBytes == nil || len(connResponseBytes) == 0 || err != nil {
		connection.Close()
		connection, err = reconnect()
		if err != nil {
			return err
		}

		connPacketBytes, err = makeCOTPConnectionPacketBytes(uint16(0x200), uint16(0x100))
		if err != nil {
			return err
		}
		connResponseBytes, err = sendRequestReadResponse(connection, connPacketBytes)
		if err != nil {
			return err
		}
	}

	_, err = unmarshalCOTPConnectionResponse(connResponseBytes)
	if err != nil {
		return err
	}

	// Negotiate S7
	requestPacketBytes, err := makeRequestPacketBytes(S7_REQUEST, makeNegotiatePDUParamBytes(), nil)
	if err != nil {
		return err
	}
	_, err = sendRequestReadResponse(connection, requestPacketBytes)
	if err != nil {
		return err
	}

	logStruct.IsS7 = true

	// Make Module Identification request
	moduleIdentificationResponse, err := readRequest(connection, S7_SZL_MODULE_IDENTIFICATION)
	if err != nil {
		return err
	}
	parseModuleIdentificationRequest(logStruct, &moduleIdentificationResponse)

	// Make Component Identification request
	componentIdentificationResponse, err := readRequest(connection, S7_SZL_COMPONENT_IDENTIFICATION)
	if err != nil {
		return err
	}
	parseComponentIdentificationResponse(logStruct, &componentIdentificationResponse)

	return nil
}

func makeCOTPConnectionPacketBytes(dstTsap uint16, srcTsap uint16) ([]byte, error) {
	var cotpConnPacket COTPConnectionPacket
	cotpConnPacket.DestinationRef = uint16(0x00) // nmap uses 0x00
	cotpConnPacket.SourceRef = uint16(0x04)      // nmap uses 0x14
	cotpConnPacket.DestinationTSAP = dstTsap
	cotpConnPacket.SourceTSAP = srcTsap
	cotpConnPacket.TPDUSize = byte(0x0a) // nmap uses 0x0a

	cotpConnPacketBytes, err := cotpConnPacket.Marshal()
	if err != nil {
		return nil, err
	}

	var tpktPacket TPKTPacket
	tpktPacket.Data = cotpConnPacketBytes
	bytes, err := tpktPacket.Marshal()
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func makeRequestPacketBytes(pduType byte, parameters []byte, data []byte) ([]byte, error) {
	var s7Packet S7Packet
	s7Packet.PDUType = pduType
	s7Packet.RequestId = S7_REQUEST_ID
	s7Packet.Parameters = parameters
	s7Packet.Data = data
	s7PacketBytes, err := s7Packet.Marshal()
	if err != nil {
		return nil, err
	}

	var cotpDataPacket COTPDataPacket
	cotpDataPacket.Data = s7PacketBytes
	cotpDataPacketBytes, err := cotpDataPacket.Marshal()
	if err != nil {
		return nil, err
	}

	var tpktPacket TPKTPacket
	tpktPacket.Data = cotpDataPacketBytes
	bytes, err := tpktPacket.Marshal()
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// Send a generic packet request and return the response
func sendRequestReadResponse(connection net.Conn, requestBytes []byte) ([]byte, error) {
	connection.Write(requestBytes)
	responseBytes, err := zgrab2.ReadAvailable(connection)
	if err != nil {
		return nil, err
	}

	return responseBytes, nil
}

func unmarshalCOTPConnectionResponse(responseBytes []byte) (cotpConnPacket COTPConnectionPacket, err error) {
	var tpktPacket TPKTPacket
	if err := tpktPacket.Unmarshal(responseBytes); err != nil {
		return cotpConnPacket, err
	}

	if err := cotpConnPacket.Unmarshal(tpktPacket.Data); err != nil {
		return cotpConnPacket, err
	}

	return cotpConnPacket, nil
}

func makeNegotiatePDUParamBytes() (bytes []byte) {
	uint16BytesHolder := make([]byte, 2)
	bytes = make([]byte, 0, 8)        // fixed param length for negotiating PDU params
	bytes = append(bytes, byte(0xf0)) // negotiate PDU function code
	bytes = append(bytes, byte(0))    // ?
	binary.BigEndian.PutUint16(uint16BytesHolder, 0x01)
	bytes = append(bytes, uint16BytesHolder...) // min # of parallel jobs
	binary.BigEndian.PutUint16(uint16BytesHolder, 0x01)
	bytes = append(bytes, uint16BytesHolder...) // max # of parallel jobs
	binary.BigEndian.PutUint16(uint16BytesHolder, 0x01e0)
	bytes = append(bytes, uint16BytesHolder...) // pdu length
	return bytes
}

func makeReadRequestParamBytes(data []byte) (bytes []byte) {
	bytes = make([]byte, 0, 16)

	bytes = append(bytes, byte(0x00)) // magic parameter
	bytes = append(bytes, byte(0x01)) // magic parameter
	bytes = append(bytes, byte(0x12)) // magic parameter
	bytes = append(bytes, byte(0x04)) // param length
	bytes = append(bytes, byte(0x11)) // ?
	bytes = append(bytes, byte((S7_SZL_REQUEST*0x10)+S7_SZL_FUNCTIONS))
	bytes = append(bytes, byte(S7_SZL_READ))
	bytes = append(bytes, byte(0))

	return bytes
}

func makeReadRequestDataBytes(szlId uint16) []byte {
	bytes := make([]byte, 0, 4)
	bytes = append(bytes, byte(0xff))
	bytes = append(bytes, byte(0x09))
	uint16BytesHolder := make([]byte, 2)
	binary.BigEndian.PutUint16(uint16BytesHolder, uint16(4)) // size of subsequent data
	bytes = append(bytes, uint16BytesHolder...)
	binary.BigEndian.PutUint16(uint16BytesHolder, szlId)
	bytes = append(bytes, uint16BytesHolder...) // szl id
	binary.BigEndian.PutUint16(uint16BytesHolder, 1)
	bytes = append(bytes, uint16BytesHolder...) // szl index

	return bytes
}

func makeReadRequestBytes(szlId uint16) ([]byte, error) {
	readRequestParamBytes := makeReadRequestParamBytes(makeReadRequestDataBytes(szlId))
	readRequestBytes, err := makeRequestPacketBytes(S7_REQUEST_USER_DATA, readRequestParamBytes, makeReadRequestDataBytes(szlId))
	if err != nil {
		return nil, err
	}

	return readRequestBytes, nil
}

func unmarshalReadResponse(bytes []byte) (S7Packet, error) {
	var tpktPacket TPKTPacket
	var cotpDataPacket COTPDataPacket
	var s7Packet S7Packet
	if err := tpktPacket.Unmarshal(bytes); err != nil {
		return s7Packet, err
	}

	if err := cotpDataPacket.Unmarshal(tpktPacket.Data); err != nil {
		return s7Packet, err
	}

	if err := s7Packet.Unmarshal(cotpDataPacket.Data); err != nil {
		return s7Packet, err
	}

	return s7Packet, nil
}

func parseComponentIdentificationResponse(logStruct *S7Log, s7Packet *S7Packet) error {
	if len(s7Packet.Data) < S7_DATA_BYTE_OFFSET {
		return errS7PacketTooShort
	}

	fields := bytes.FieldsFunc(s7Packet.Data[S7_DATA_BYTE_OFFSET:], func(c rune) bool {
		return int(c) == 0
	})

	for i := len(fields) - 1; i >= 0; i-- {
		switch i {
		case 0:
			logStruct.System = string(fields[i][1:]) // exclude index byte
		case 1:
			logStruct.Module = string(fields[i][1:])
		case 2:
			logStruct.PlantId = string(fields[i][1:])
		case 3:
			logStruct.Copyright = string(fields[i][1:])
		case 4:
			logStruct.SerialNumber = string(fields[i][1:])
		case 5:
			logStruct.ModuleType = string(fields[i][1:])
		case 6:
			logStruct.ReservedForOS = string(fields[i][1:])
		case 7:
			logStruct.MemorySerialNumber = string(fields[i][1:])
		case 8:
			logStruct.CpuProfile = string(fields[i][1:])
		case 9:
			logStruct.OEMId = string(fields[i][1:])
		case 10:
			logStruct.Location = string(fields[i][1:])
		}
	}

	return nil
}

// moduleIDData represents the data structure of the system status list.
// See https://cache.industry.siemens.com/dl/files/574/1214574/att_44504/v1/SFC_e.pdf
// 33.5 SSL-ID W#16#xy11 - Module Identification
type moduleIDData struct {
	Index  uint16 // Index of an identification data record
	MIFB   string // 20 bytes string
	BGTyp  uint16 // Reserved, 1 word
	Ausbg1 uint16 // Version of the module, 1 word
	Ausbg2 uint16 // Remaining numbers of the version ID, 1 word
}

// parseModuleIDDataRecord parses a byte slice into a DataRecord.
func parseModuleIDDataRecord(data []byte) (*moduleIDData, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("data slice too short to contain a valid DataRecord")
	}

	return &moduleIDData{
		Index:  binary.BigEndian.Uint16(data[:2]),
		MIFB:   string(data[2:22]),
		BGTyp:  binary.BigEndian.Uint16(data[22:24]),
		Ausbg1: binary.BigEndian.Uint16(data[24:26]),
		Ausbg2: binary.BigEndian.Uint16(data[26:28]),
	}, nil
}

// Constructs the version number from a moduleIDData record.
func getVersionNumber(record *moduleIDData) string {
	// The major, minor, and patch versions are stored in the lower 8 bits of Ausbg1,
	// the upper 8 bits of Ausbg2, and the lower 8 bits of Ausbg2, respectively.
	major := record.Ausbg1 & 0xFF
	minor := record.Ausbg2 >> 8
	patch := record.Ausbg2 & 0xFF

	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

func parseModuleIdentificationRequest(logStruct *S7Log, s7Packet *S7Packet) error {
	if len(s7Packet.Data) < S7_DATA_BYTE_OFFSET {
		return errS7PacketTooShort
	}

	// Skip the first 4 bytes (return code, transport size, length)
	// And the next 4 bytes (SSLID, INDEX)
	offset := 8

	// Parse LENTHDR and N_DR from the header
	recordLen := int(binary.BigEndian.Uint16(s7Packet.Data[offset : offset+2]))
	offset += uint16Size

	numRecords := int(binary.BigEndian.Uint16(s7Packet.Data[offset : offset+2]))
	offset += uint16Size

	// Check if the data record length and number of data records are valid
	if recordLen != s7ModuleIdRecordSize || numRecords*recordLen > len(s7Packet.Data)-offset {
		return fmt.Errorf("invalid data record length or number of data records")
	}

	// Now parse the data records, considering each one is 28 bytes long after the header
	for i := 0; i < int(numRecords); i++ {
		record, err := parseModuleIDDataRecord(s7Packet.Data[offset : offset+recordLen])
		if err != nil {
			return fmt.Errorf("failed parsing data record %d: %v", i, err)
		}

		switch record.Index {
		case s7ModuleIdModuleIndex:
			logStruct.ModuleId = record.MIFB
		case s7ModuleIdHardwareIndex:
			logStruct.Hardware = getVersionNumber(record)
		case s7ModuleIdFirmwareIndex:
			logStruct.Firmware = getVersionNumber(record)
		}

		offset += recordLen
	}

	return nil
}

func readRequest(connection net.Conn, slzId uint16) (packet S7Packet, err error) {
	readRequestBytes, err := makeReadRequestBytes(slzId)
	if err != nil {
		return packet, err
	}
	readResponse, err := sendRequestReadResponse(connection, readRequestBytes)
	if err != nil {
		return packet, err
	}
	packet, err = unmarshalReadResponse(readResponse)
	if err != nil {
		return packet, err
	}

	return packet, nil
}
