package modbus

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

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// MEIResponse is the parsed data field from the 0x2B/0x0E response.
type MEIResponse struct {
	// ConformityLevel specifies the confirmity level of the device and the type of supported access.
	// Valid values include 0x01, 0x02, 0x03, for basic, regular, extended stream access, and
	// 8x81, 0x82, 0x83 for basic, regular, extended stream/individual access.
	ConformityLevel int `json:"conformity_level"`

	// MoreFollows specifies whether more data follows. Strictly should be 00 or FF, but we take any nonzero number
	// to mean that more data follows.
	MoreFollows bool `json:"more_follows"`

	// NextObjectID gives the next object ID if MoreFollows is set, otherwise it should be 0x00.
	NextObjectID int `json:"next_object_id"`

	// ObjectCount gives the number of items returned.
	ObjectCount int `json:"object_count"`

	// Objects is a set of object ID/value pairs returned by the server.
	Objects MEIObjectSet `json:"objects,omitempty"`
}

// MEIObjectSet wraps the list of object ID/value pairs, encoding them as a dict of ID name -> value
type MEIObjectSet []MEIObject

// MarshalJSON encodes the object ID list as a map of { "obj.OID.Name()": obj.Value }
func (ms *MEIObjectSet) MarshalJSON() ([]byte, error) {
	enc := make(map[string]string, len(*ms))
	for _, obj := range *ms {
		enc[obj.OID.Name()] = obj.Value
	}
	return json.Marshal(enc)
}

// MEIObject wraps the ID/value pair in the 0x2B/0x0E response.
type MEIObject struct {
	// OID is the object identifier.
	OID MEIObjectID
	// Value is the value for that object identifier.
	Value string
}

// MEIObjectID is the numeric identifier used by the server to identify different data.
type MEIObjectID int

const (
	// OIDVendor identifies the vendor name. Mandatory ASCII String, category = basic.
	OIDVendor MEIObjectID = 0

	// OIDProductCode identifies the product code. Mandatory ASCII String, category = basic.
	OIDProductCode MEIObjectID = 1

	// OIDRevision identifies the MajorMinorRevision. Mandatory ASCII String, category = basic.
	OIDRevision MEIObjectID = 2

	// OIDVendorURL identifies the vendor URL. Optional ASCII String, category = regular.
	OIDVendorURL MEIObjectID = 3

	// OIDProductName identifies the product name. Optional ASCII String, category = regular.
	OIDProductName MEIObjectID = 4

	// OIDModelName identifies the model name. Optional ASCII String, category = regular.
	OIDModelName MEIObjectID = 5

	// OIDUserApplicationName identifies the user application name. Optional ASCII String, category = regular.
	OIDUserApplicationName MEIObjectID = 6
)

var meiObjectNames = []string{
	"vendor",
	"product_code",
	"revision",
	"vendor_url",
	"product_name",
	"model_name",
	"user_application_name",
}

// Name maps the object ID to its friendly name; if the ID is not on the list, it returns "oid_$(id)".
func (m *MEIObjectID) Name() string {
	oid := int(*m)
	var name string
	if oid >= len(meiObjectNames) || oid < 0 {
		name = "oid_" + strconv.Itoa(oid)
	} else {
		name = meiObjectNames[oid]
	}
	return name
}

// MarshalJSON encodes the identifier as its friendly name.
func (m *MEIObject) MarshalJSON() ([]byte, error) {
	enc := make(map[string]interface{}, 1)
	name := m.OID.Name()
	enc[name] = m.Value
	return json.Marshal(enc)
}

// ExceptionResponse wraps the exception returned by the server.
type ExceptionResponse struct {
	// ExceptionFunction is the function to which the server is responding -- namely, the value of the FunctionCode in
	// the response with the high bit masked off.
	ExceptionFunction FunctionCode `json:"exception_function"`

	// ExceptionType is the type code representing the exception.
	// For details see e.g. section 7 of http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
	ExceptionType byte `json:"exception_type"`
}

// ModbusEvent is the response object. Either MEIResponse or ExceptionResponse will be set.
type ModbusEvent struct {
	// Length is the data length the server claimed to return in the header. Should be len(Response) + 1 (the function
	// code is included)
	Length int `json:"length"`

	// UnitID is the unit ID for which the server is responding. If request unit ID was nonzero, should match that.
	UnitID int `json:"unit_id"`

	// Function is the response function code. The high bit indicates the presence of an exception (set -> exception).
	Function FunctionCode `json:"function_code"`

	// Response is the response data (not including the function code).
	Response []byte `json:"raw_response,omitempty"`

	// MEIResponse is the parsed response; it is present if the response was decoded successfully and there was no
	// exception.
	MEIResponse *MEIResponse `json:"mei_response,omitempty"`

	// ExceptionResponse is the parsed exception; it is present if the response was decoded successfully and there was
	// an exception (i.e. the high bit of Function is set).
	ExceptionResponse *ExceptionResponse `json:"exception_response,omitempty"`

	// Raw is the full raw response from the server, including the header.
	Raw []byte `json:"raw,omitempty"`
}

// IsException returns true if this response indicates an exception has occurred.
func (m *ModbusResponse) IsException() bool {
	return (m.Function&0x80 != 0)
}

// getEvent does basic validation parsing, and on success, returns the event; on failure, it returns nil and the error,
// which should be interpreted as a protocol error / failed detection.
func (m *ModbusResponse) getEvent(strict bool) (*ModbusEvent, error) {
	ret := &ModbusEvent{
		Length:   m.Length,
		UnitID:   m.UnitID,
		Function: m.Function,
		Response: m.Data,
		Raw:      m.Raw,
	}
	if m.IsException() {
		ex, err := m.getExceptionResponse(strict)
		if err != nil {
			return nil, err
		}
		ret.ExceptionResponse = ex
	} else {
		// TODO: This is only valid for 0x0E.
		mei, err := m.getMEIResponse(strict)
		if err != nil {
			return nil, err
		}
		ret.MEIResponse = mei
	}
	return ret, nil
}

func (m *ModbusResponse) getExceptionResponse(strict bool) (*ExceptionResponse, error) {
	exceptionFunction := m.Function & 0x7F
	var exceptionType byte
	if len(m.Data) > 0 {
		exceptionType = m.Data[0]
	} else if strict {
		return nil, fmt.Errorf("Empty response body on error for function 0x%02x", exceptionFunction)
	}
	return &ExceptionResponse{
		ExceptionFunction: exceptionFunction,
		ExceptionType:     exceptionType,
	}, nil
}

func (m *ModbusResponse) getMEIResponse(strict bool) (*MEIResponse, error) {
	if m.Function != FunctionCodeMEI {
		return nil, fmt.Errorf("Invalid function code 0x%02x", m.Function)
	}
	if len(m.Data) < 6 {
		return nil, fmt.Errorf("Response too short (%d bytes)", len(m.Data))
	}
	meiType := m.Data[0]
	if meiType != 0x0E {
		return nil, fmt.Errorf("Invalid response data (expected 0xee, got 0x%02x)", meiType)
	}
	// TODO: Allow different values here
	readType := m.Data[1]
	if readType != 1 {
		return nil, fmt.Errorf("Invalid response data (expected 0x01, got 0x%02x)", readType)
	}
	conformityLevel := m.Data[2]
	moreFollows := (m.Data[3] != 0)
	if strict && m.Data[3] != 0x00 && m.Data[3] != 0xFF {
		return nil, fmt.Errorf("Invalid response data (expected 0x00 or 0xff for MoreFollows, got 0x%02x)", m.Data[3])
	}
	nextObject := m.Data[4]
	if strict && (!moreFollows && nextObject != 0) {
		return nil, fmt.Errorf("For MoreFollows == 0x00, expected NextObjectID == 0x00 (got 0x%02x)", nextObject)
	}
	objectCount := m.Data[5]
	objects := make([]MEIObject, objectCount)
	it := 6
	for idx := range objects {
		n, obj := parseMEIObject(m.Data[it:])
		it += n
		if obj == nil {
			break
		}
		objects[idx] = *obj
	}
	return &MEIResponse{
		ConformityLevel: int(conformityLevel),
		MoreFollows:     moreFollows,
		NextObjectID:    int(nextObject),
		ObjectCount:     int(objectCount),
		Objects:         objects,
	}, nil
}

func parseMEIObject(objectBytes []byte) (int, *MEIObject) {
	length := len(objectBytes)
	if length < 2 {
		return length, nil
	}
	oid := objectBytes[0]
	objLen := int(objectBytes[1])
	if length < 2+objLen {
		return length, nil
	}
	s := string(objectBytes[2 : 2+objLen])
	obj := MEIObject{
		OID:   MEIObjectID(oid),
		Value: s,
	}
	return 2 + objLen, &obj
}

// FunctionCode identifies the Modbus function being queried.
type FunctionCode byte

// ExceptionFunctionCode represents the function code corresponding to an exception -- that is, with the high bit set.
type ExceptionFunctionCode byte

// ExceptionCode represents the exception description codes.
type ExceptionCode byte

// ModbusRequest wraps the Modbus ApplicationDataUnit (ADU).
type ModbusRequest struct {
	// UnitID is the target unit ID. 0 can get special treatment (ignored, invalid, or treated as broadcast).
	UnitID int

	// FunctionCode identifies the function for the server to execute.
	Function FunctionCode

	//  Deta is the payload for the request, its format depends on the FunctionCode.
	Data []byte
}

// MarshalRequest marshals the request for transport to the server.
func (c *Conn) MarshalRequest(r *ModbusRequest) (data []byte, err error) {
	data = make([]byte, 7+1+len(r.Data))
	// Request ID: default ZG
	binary.BigEndian.PutUint16(data[0:2], c.scanner.config.RequestID)
	// Protocol: must be 0
	binary.BigEndian.PutUint16(data[2:4], 0)
	msglen := len(r.Data) + 2 // unit ID and function
	binary.BigEndian.PutUint16(data[4:6], uint16(msglen))
	// leaving UnitID == 0 keeps the original zgrab behavior (which hangs on the modbus simulator -- "station #0 so no
	// response allowed")
	// similarly, if the identified unit is offline, it hangs with "Station ID <X> off-line, no response sent".
	data[6] = byte(r.UnitID)
	data[7] = byte(r.Function)
	copy(data[8:], r.Data)
	return
}

// ModbusResponse wraps the data returned by the server in response to the ModbusRequest.
type ModbusResponse struct {
	// Length is the number of bytes the server says it will return.
	Length int

	// UnitID identifies the unit this response pertains to.
	UnitID int

	// Function is the function code returned by the server (which may have the high bit set to indicate an exception).
	Function FunctionCode

	// Data is payload, its format depends on the function code. Should be Length - 1 bytes.
	Data []byte

	// Raw is the actual data returned by the server, including the header.
	Raw []byte
}

// GetModbusResponse reads the response from the server and does some minimal parsing.
func (c *Conn) GetModbusResponse() (*ModbusResponse, error) {
	header := make([]byte, 7)
	_, err := io.ReadFull(c.getUnderlyingConn(), header)
	if err != nil {
		return nil, fmt.Errorf("modbus: could not get response: %s", err.Error())
	}

	// first 4 bytes should be known, verify them
	requestID := binary.BigEndian.Uint16(header[0:2])
	if requestID != c.scanner.config.RequestID {
		return nil, fmt.Errorf("modbus: requestID did not match (got 0x%02x, expected 0x%02x)", requestID, c.scanner.config.RequestID)
	}
	protocolID := binary.BigEndian.Uint16(header[2:4])
	if protocolID != 0 {
		return nil, fmt.Errorf("modbus: protocol ID did not match (got 0x%02x, expected 0x00)", protocolID)
	}
	msglen := int(binary.BigEndian.Uint16(header[4:6]))
	unitID := int(header[6])

	// less than 1 because it's msglen - 1
	if msglen < 1 {
		return nil, errors.New("modbus: invalid message length")
	}

	body := make([]byte, msglen-1)
	cnt := 0
	// One of the bytes in length counts as part of the header
	var readError error
	for cnt < len(body) {
		var n int
		n, readError = c.getUnderlyingConn().Read(body[cnt:])
		cnt += n

		if readError != nil {
			// Some servers return a message length of 09, but stop sending data after the two-byte error
			body = body[:cnt]
			break
		}
	}

	if readError == io.EOF {
		readError = nil
	}
	raw := make([]byte, len(header)+len(body))
	copy(raw[0:7], header)
	copy(raw[7:], body)

	if len(body) < 1 {
		return nil, readError
	}

	//TODO this really should be done by a more elegant unmarshaling function
	return &ModbusResponse{
		Length:   msglen,
		UnitID:   unitID,
		Function: FunctionCode(body[0]),
		Data:     body[1:],
		Raw:      raw,
	}, readError
}

// FunctionCode strips the high bit off of the exception function code, to get the function for which the server is
// responding.
func (e ExceptionFunctionCode) FunctionCode() FunctionCode {
	code := byte(e) & byte(0x7f)
	return FunctionCode(code)
}

// ExceptionFunctionCode gets the code that the server would return in an exception to the given function code.
func (c FunctionCode) ExceptionFunctionCode() ExceptionFunctionCode {
	code := byte(c) | byte(0x80)
	return ExceptionFunctionCode(code)
}

// IsException checks if the given function code is an exception (i.e. its high bit is set).
func (c FunctionCode) IsException() bool {
	return (byte(c) & 0x80) == 0x80
}

// ModbusFunctionEncapsulatedInterface identifies the MEI read function.
var ModbusFunctionEncapsulatedInterface = FunctionCode(0x2B)

const (
	// FunctionCodeMEI identifies the MEI read function.
	FunctionCodeMEI = FunctionCode(0x2B)
)
