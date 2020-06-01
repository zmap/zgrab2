/*
* ZGrab Copyright 2015 Regents of the University of Michigan
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not
* use this file except in compliance with the License. You may obtain a copy
* of the License at http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
* implied. See the License for the specific language governing
* permissions and limitations under the License.
 */

package dnp3

import (
	"encoding/binary"
	"io"
	"net"
	"errors"

	"github.com/zmap/zgrab2"
)

// DNP3 Flags
const (
	LINK_MIN_HEADER_LENGTH        = 10     // minimum link header length in bytes
	LINK_START_FIELD              = 0x0564 // Pre-set 2-byte start field
	LINK_DIR_BIT                  = 1      // Direction bit
	LINK_PRM_BIT                  = 1      // Primary message bit
	LINK_FCB_BIT                  = 0      // Frame count bit
	LINK_FCV_BIT                  = 0      // Frame count valid bit
	LINK_BROADCAST_ADDRESS        = 0x0001 // Broadcast address w/o mandatory application response
	LINK_UNCONFIRMED_USER_DATA_FC = 0x4    // don't require link layer response function code
	LINK_REQUEST_STATUS_FC        = 0x9    // 4-bit function code for requesting link status
	LINK_STATUS_FC                = 0xB    // 4-bit response function code for link status
	FUNCTION_CODE_NOT_SUPPORTED   = 0xF    // Unsupported function code response
	TRANSPORT_START_SEQUENCE      = 0x00   // starting sequence number for transport packet
	APP_START_SEQUENCE            = 0x00   // starting sequence number for application packet
	APP_CON_BIT                   = 0      // no app acknowledgement
	APP_UNS_BIT                   = 0      // not an unsolicited response
	APP_FUNC_CODE_READ            = 0x01   // 1-byte function code for reading
	APP_GROUP_0                   = 0x00   // group 0 refers to all static data
	APP_GROUP_0_QUALIFIER         = 0x00   // objects are packed without index prefix
	APP_GROUP_0_RANGE             = 0x0000 // no range due to no qualifier
	APP_GROUP_0_SOFTWARE_VERSION  = 0xF2   // group 0 attribute - device manufacturer's software version
	APP_GROUP_0_HARDWARE_VERSION  = 0xF3   // group 0 attribute - device manufacturer's hardware version
	APP_GROUP_0_LOCATION          = 0xF5   // group 0 attribute - device location
	APP_GROUP_0_DEVICE_ID         = 0xF6   // group 0 attribute - device application id
	APP_GROUP_0_DEVICE_NAME       = 0xF7   // group 0 attribute - device name
	APP_GROUP_0_SERIAL_NUMBER     = 0xF8   // group 0 attribute - device manufacturer's serial number
	APP_GROUP_0_DNP3_SUBSET       = 0xF9   // subset of the dnp3 protocol that is implemented
	APP_GROUP_0_PRODUCT_NAME      = 0xFA   // group 0 attribute - device manufacturer's product name and model
	APP_GROUP_0_ALL_ATTRIBUTES    = 0xFE   // get all available group 0 attributes in single response
	APP_GROUP_0_LIST_ATTRIBUTES   = 0xFF   // list available group 0 attributes
)

var linkBatchRequest []byte

func init() {
	linkBatchRequest = makeLinkRequestBatch(0x0000, 1, 0x0000, 100)
}

func GetDNP3Banner(logStruct *DNP3Log, connection net.Conn) (err error) {
	connection.Write(linkBatchRequest)

	data, err := zgrab2.ReadAvailable(connection)

	if err != nil && err != io.EOF {
		return err
	}

	if len(data) >= LINK_MIN_HEADER_LENGTH && binary.BigEndian.Uint16(data[0:2]) == LINK_START_FIELD {
		logStruct.IsDNP3 = true
		logStruct.RawResponse = data
		return nil
	}

	return zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("Invalid response for DNP3"))
}

func makeLinkStatusRequest(dstAddress uint16) []byte {
	return makeLinkHeader(0x0000, dstAddress, LINK_REQUEST_STATUS_FC, 0) // no transport/app layer
}

func makeBannerRequest(dstAddress uint16) []byte {
	var request []byte

	transportLayer := makeTransportHeader()
	appLayer := makeAppAttrRequest()
	linkLayer := makeLinkHeader(0x0000, dstAddress, LINK_UNCONFIRMED_USER_DATA_FC, len(transportLayer)+len(appLayer))

	request = append(request, linkLayer...)
	request = append(request, transportLayer...)
	request = append(request, appLayer...)

	return request
}

func setBit(b byte, position uint32, value int) (result byte) {

	if value == 1 {
		result = b | (1 << position)
	} else if value == 0 {
		result = b & (^(1 << position))
	}

	return result
}

/**
 * Creates a link-layer header for a given data link function code.
 * MsgLength is the length of the transport + application layers
 */
func makeLinkHeader(srcAddress uint16, dstAddress uint16, functionCode int, msgLength int) []byte {
	linkHeader := make([]byte, 0, LINK_MIN_HEADER_LENGTH)

	// DATA LINK LAYER

	// 2-byte start field
	startField := make([]byte, 2)
	binary.BigEndian.PutUint16(startField, LINK_START_FIELD)
	linkHeader = append(linkHeader, startField...)

	//length byte
	lengthByte := byte(0x5 + msgLength)
	linkHeader = append(linkHeader, lengthByte)

	//link control byte
	linkControlByte := byte(functionCode)
	linkControlByte = setBit(linkControlByte, 7, LINK_DIR_BIT)
	linkControlByte = setBit(linkControlByte, 6, LINK_PRM_BIT)
	linkControlByte = setBit(linkControlByte, 5, LINK_FCB_BIT)
	linkControlByte = setBit(linkControlByte, 4, LINK_FCV_BIT)
	linkHeader = append(linkHeader, linkControlByte)

	// 2-byte destination address
	destinationAddress := make([]byte, 2)
	binary.LittleEndian.PutUint16(destinationAddress, dstAddress)
	linkHeader = append(linkHeader, destinationAddress...)

	// 2-byte source address
	sourceAddress := make([]byte, 2)
	binary.LittleEndian.PutUint16(sourceAddress, srcAddress)
	linkHeader = append(linkHeader, sourceAddress...)

	//CRC
	crcCheck := make([]byte, 2)
	binary.LittleEndian.PutUint16(crcCheck, Crc16(linkHeader))
	linkHeader = append(linkHeader, crcCheck...)

	return linkHeader
}

func makeTransportHeader() []byte {
	var transportHeader []byte

	transportByte := byte(TRANSPORT_START_SEQUENCE)
	transportByte = setBit(transportByte, 7, 1) //first transport segment
	transportByte = setBit(transportByte, 6, 1) //last transport segment
	transportHeader = append(transportHeader, transportByte)

	return transportHeader
}

// Make an application layer []byte request for device attributes
func makeAppAttrRequest() []byte {
	var attrRequest []byte

	// control byte
	appControlByte := byte(APP_START_SEQUENCE)
	appControlByte = setBit(appControlByte, 7, 1)           //first app layer segment
	appControlByte = setBit(appControlByte, 6, 1)           //last app layer segment
	appControlByte = setBit(appControlByte, 5, APP_CON_BIT) //
	appControlByte = setBit(appControlByte, 4, APP_UNS_BIT) //last app layer segment
	attrRequest = append(attrRequest, appControlByte)

	attrRequest = append(attrRequest, byte(APP_FUNC_CODE_READ)) // function code

	// Object header
	attrRequest = append(attrRequest, byte(APP_GROUP_0))                // group to be reading from
	attrRequest = append(attrRequest, byte(APP_GROUP_0_ALL_ATTRIBUTES)) // get all attributes
	attrRequest = append(attrRequest, byte(APP_GROUP_0_QUALIFIER))      // no object indexing
	appIndexRange := make([]byte, 2)
	binary.LittleEndian.PutUint16(appIndexRange, APP_GROUP_0_RANGE) // range is irrelevant due to no indexing
	attrRequest = append(attrRequest, appIndexRange...)

	return attrRequest
}

func makeLinkRequestBatch(startingSrcAddress uint16, numberSrc int, startingDestAddress uint16, numberDest int) []byte {
	var batchRequest []byte
	for src, srcCount := startingSrcAddress, 0; srcCount < numberSrc; src, srcCount = src+1, srcCount+1 {
		for dest, destCount := startingDestAddress, 0; destCount < numberDest; dest, destCount = dest+1, destCount+1 {
			batchRequest = append(batchRequest, makeLinkHeader(src, dest, LINK_REQUEST_STATUS_FC, 0)...)
		}
	}

	return batchRequest
}
