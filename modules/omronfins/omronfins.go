package omronfins

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strings"
)

const (
	QUERY_UDP_PACKET       = "800002000000006300ef050100"
	REQ_ADDR_PACKET        = "46494e530000000c000000000000000000000000"
	QUERY_TCP_PACKET_PART1 = "46494e5300000015000000020000000080000200"
	QUERY_TCP_PACKET_PART2 = "000000ef05050100"

)

var NOT_ENOUGH_DATA = errors.New("not enough data to Omron Fins Header")
var NOT_OMRON_FINS = errors.New("not Omron-Fins response")

var queryUDPBytes []byte
var queryReqAddrBytes []byte
var queryTcpPart1Bytes []byte
var queryTcpPart2Bytes []byte

func init() {
	var err error
	queryUDPBytes, err = hex.DecodeString(QUERY_UDP_PACKET)
	if err != nil {
		panic("Could not decode Omron-Fins query")
	}

	queryReqAddrBytes, err = hex.DecodeString(REQ_ADDR_PACKET)
	if err != nil {
		panic("Could not decode Omron-Fins query")
	}

	queryTcpPart1Bytes, err = hex.DecodeString(QUERY_TCP_PACKET_PART1)
	if err != nil {
		panic("Could not decode Omron-Fins query")
	}

	queryTcpPart2Bytes, err = hex.DecodeString(QUERY_TCP_PACKET_PART2)
	if err != nil {
		panic("Could not decode Omron-Fins query")
	}
}

var MemoryCardTypeMap = map[int]string{
	0: "No memory card",
	1: "SPARM",
	2: "EPROM",
	3: "EEPROM",
}
var ResponseCodeMap = map[int]string{
	0x0000: "Normal completion",
	0x0001: "Service was interrupted",
	0x0101: "Local node not part of Network",
	0x0102: "Token time-out, destination node busy",
	0x0103: "Number of transmit retries exceeded",
	0x0104: "Maximum number of frames exceeded",
	0x0105: "Node number setting error (range)",
	0x0106: "Node number duplication error",
	0x0201: "Destination node not part of Network",
	0x0202: "No node with the specified node number",
	0x0203: "Third node not part of Network : Broadcasting was specified",
	0x0204: "Busy error, error still exists",
	0x0205: "Response time-out",
	0x0301: "Error occurred : ERC indicator is lit",
	0x0302: "CPU error occurred in the PC at the destination node",
	0x0303: "A controller error has prevented a normal response",
	0x0304: "Node number setting error",
	0x0401: "An undefined command has been used",
	0x0402: "Cannot process command because the specified unit model or version is wrong",
	0x0501: "Destination node number is not set in the routing table",
	0x0502: "Routing table isn't registered",
	0x0503: "Routing table error",
	0x0504: "Max relay nodes (2) was exceeded",
	0x1001: "The command is longer than the max permissible length",
	0x1002: "The command is shorter than the min permissible length",
	0x1003: "The designated number of data items differs from the actual number",
	0x1004: "An incorrect command format has been used",
	0x1005: "An incorrect header has been used",
	0x1101: "Memory area code invalid or DM is not available",
	0x1102: "Access size is wrong in command",
	0x1103: "First address in inaccessible area",
	0x1104: "The end of specified word range exceeds acceptable range",
	0x1106: "A non-existent program number",
	0x1109: "The size of data items in command block are wrong",
	0x110A: "The IOM break function cannot be executed",
	0x110B: "The response block is longer than the max length",
	0x110C: "An incorrect parameter code has been specified",
	0x2002: "The data is protected",
	0x2003: "Registered table does not exist",
	0x2004: "Search data does not exist",
	0x2005: "Non-existent program number",
	0x2006: "Non-existent file",
	0x2007: "Verification error",
	0x2101: "Specified area is read-only",
	0x2102: "The data is protected",
	0x2103: "Too many files open",
	0x2105: "Non-existent program number",
	0x2106: "Non-existent file",
	0x2107: "File already exists",
	0x2108: "Data cannot be changed",
	0x2201: "The mode is wrong (executing)",
	0x2202: "The mode is wrong (stopped)",
	0x2203: "The PC is in the PROGRAM mode",
	0x2204: "The PC is in the DEBUG mode",
	0x2205: "The PC is in the MONITOR mode",
	0x2206: "The PC is in the RUN mode",
	0x2207: "The specified node is not the control node",
	0x2208: "The mode is wrong and the step cannot be executed",
	0x2301: "The file device does not exist where specified",
	0x2302: "The specified memory does not exist",
	0x2303: "No clock exists",
	0x2401: "Data link table is incorrect",
	0x2502: "Parity / checksum error occurred",
	0x2503: "I/O setting error",
	0x2504: "Too many I/O points",
	0x2505: "CPU bus error",
	0x2506: "I/O duplication error",
	0x2507: "I/O bus error",
	0x2509: "SYSMAC BUS/2 error",
	0x250A: "Special I/O Unit error",
	0x250D: "Duplication in SYSMAC BUS word allocation",
	0x250F: "A memory error has occurred",
	0x2510: "Terminator not connected in SYSMAC BUS system",
	0x2601: "The specified area is not protected",
	0x2602: "An incorrect password has been specified",
	0x2604: "The specified area is protected",
	0x2605: "The service is being executed",
	0x2606: "The service is not being executed",
	0x2607: "Service cannot be execute from local node",
	0x2608: "Service cannot be executed settings are incorrect",
	0x2609: "Service cannot be executed incorrect settings in command data",
	0x260A: "The specified action has already been registered",
	0x260B: "Cannot clear error, error still exists",
	0x3001: "The access right is held by another device",
	0x4001: "Command aborted with ABORT command",
}

type DeviceInfo struct {
	// Response code name of the query request of the device: taken from the map:ResponseCodeMap
	ResponseCodeVal string `json:"response_code_val"`

	// The value of the response code of the query request
	ResponseCode int `json:"response_code"`

	// The controller model
	ControllerModel string `json:"controller_model"`

	// The controller firmware version
	ControllerVersion string `json:"controller_version"`

	// Description string of the system
	ForSystemUse string `json:"for_system_use"`

	// The ladder logic program size that runs over the controller
	ProgramAreaSize int `json:"program_area_size"`

	// The input/ouput memory size of the controller
	IOMsize int `json:"io_msize"`

	//No. DM Words of the controller
	NoDMSize int `json:"no_dm_size"`

	// Timer/Counter value of the controller
	Timer int `json:"time_counter"`

	// Expansion DM Size of the controller
	ExpansionDMSize int `json:"expansion_dm_size"`

	// Number of transitions that controller did
	NoOfTransitions int `json:"no_of_transitions"`

	// The type of the memory card that is connected to the controller: taken from the map MemoryCardTypeMap
	MemoryCardType int `json:"memory_card_type"`

	// the memory card type value
	MemoryCardTypeVal string `json:"memory_card_type_val"`

	// The size of the memory card
	MemoryCardSize int `json:"memory_card_size"`
}

const HeaderSize = 12
const TCPHEADERSIZE = 16

func GetDeviceInfo(response []byte, length int, offset int, result *DeviceInfo) {
	result.ResponseCode = int(binary.BigEndian.Uint16(response[offset : offset+2]))
	val, ok := ResponseCodeMap[result.ResponseCode]
	if !ok {
		result.ResponseCodeVal = "Unknown response code"
	} else {
		result.ResponseCodeVal = val
	}
	offset = offset + 2
	if result.ResponseCode == 0 && length >= offset+92 {
		result.ControllerModel = strings.TrimSpace(strings.Split(string(response[offset:offset+0x14]), "\x00")[0])
		offset += 0x14
		result.ControllerVersion = strings.TrimSpace(strings.Split(string(response[offset:offset+0x14]), "\x00")[0])
		offset += 0x14
		result.ForSystemUse = strings.TrimSpace(strings.Split(string(response[offset:offset+40]), "\x00")[0])
		offset += 40
		result.ProgramAreaSize = int(binary.BigEndian.Uint16(response[offset : offset+2]))
		offset += 2
		result.IOMsize = int(response[offset])
		offset += 1
		result.NoDMSize = int(binary.BigEndian.Uint16(response[offset : offset+2]))
		offset += 2
		result.Timer = int(response[offset])
		offset += 1
		result.ExpansionDMSize = int(response[offset])
		offset += 1
		result.NoOfTransitions = int(binary.BigEndian.Uint16(response[offset : offset+2]))
		offset += 2
		result.MemoryCardType = int(response[offset])
		offset += 1
		val, ok := MemoryCardTypeMap[result.MemoryCardType]
		if !ok {
			result.MemoryCardTypeVal = "Unknown memory card type"
		} else {
			result.MemoryCardTypeVal = val
		}
		result.MemoryCardSize = int(binary.BigEndian.Uint16(response[offset : offset+2]))
	}
}

func QueryDeviceTCP(Con net.Conn) (DeviceInfo, error) {
	result := DeviceInfo{}
	_, err := Con.Write(queryReqAddrBytes)
	if err != nil {
		return result, err
	}
	response := make([]byte, 256, 1024)
	read, err := Con.Read(response)
	if err != nil {
		return result, err
	}
	if read >= 24 && string(response[0:4]) == "FINS" {
		clientAddress := response[23:24]
		queryPacket := make([]byte, 0, 128)
		queryPacket = append(queryPacket, queryTcpPart1Bytes...)
		queryPacket = append(queryPacket, clientAddress...)
		queryPacket = append(queryPacket, queryTcpPart2Bytes...)
		_, err := Con.Write(queryPacket)
		if err != nil {
			return result, err
		}
		read, err := Con.Read(response)
		if err != nil {
			return result, err
		}
		if read < HeaderSize+TCPHEADERSIZE {
			return result, NOT_ENOUGH_DATA
		} else if (response[TCPHEADERSIZE] == 0xc0 || response[TCPHEADERSIZE] == 0xc1) &&
			(binary.BigEndian.Uint16(response[TCPHEADERSIZE+10:TCPHEADERSIZE+12]) == 0x501) && read >= 14 {
			GetDeviceInfo(response, read, TCPHEADERSIZE+12, &result)
			return result, nil
		}

	}

	return result, NOT_OMRON_FINS
}

func QueryDeviceUDP(Con net.Conn) (DeviceInfo, error) {
	result := DeviceInfo{}
	_, err := Con.Write(queryUDPBytes)
	if err != nil {
		return result, err
	}
	response := make([]byte, 106, 512)
	read, err := Con.Read(response)
	if err != nil {
		return result, err
	}

	if read < HeaderSize {
		return result, NOT_ENOUGH_DATA
	} else if (response[0] == 0xc0 || response[0] == 0xc1) && (binary.BigEndian.Uint16(response[10:12]) == 0x501) && read >= 14 {
		GetDeviceInfo(response, read, 12, &result)
		return result, nil
	}

	return result, NOT_OMRON_FINS
}
