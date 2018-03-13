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

package telnet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
)

// RFC 854 - https://tools.ietf.org/html/rfc854
const (
	// IAC means INTERPRET AS COMMAND.
	IAC                = byte(255)

	// DONT means don't use these options.
	DONT               = byte(254)

	// DO means do use these options.
	DO                 = byte(253)

	// WONT means these options won't be used.
	WONT               = byte(252)

	// WILL means these options will be used.
	WILL               = byte(251)

	// GO_AHEAD is the special go ahead command.
	GO_AHEAD           = byte(249)

	// IAC_CMD_LENGTH gives the length of the special IAC command (inclusive).
	IAC_CMD_LENGTH     = 3

	// READ_BUFFER_LENGTH is the size of the read buffer.
	READ_BUFFER_LENGTH = 8192
)

// TelnetOption provides mappings of telnet option enum values to/from their friendly names.
type TelnetOption uint16

// Name gets the friendly name of the TelnetOption (or "unknown" if it is not recognized).
func (opt *TelnetOption) Name() string {
	name, ok := optionToName[int(*opt)]
	if !ok {
		return "unknown"
	}
	return name
}

// MarshalJSON returns the JSON-encoded friendly name of the telnet option.
func (opt *TelnetOption) MarshalJSON() ([]byte, error) {
	out := struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}{
		opt.Name(),
		int(*opt),
	}
	return json.Marshal(&out)
}

// UnmarshalJSON returns the TelnetOption enum value from its JSON-encoded friendly name.
func (opt *TelnetOption) UnmarshalJSON(b []byte) error {
	aux := struct {
		Value int `json:"value"`
	}{}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if aux.Value < 0 || aux.Value > 255 {
		return errors.New("Invalid byte value")
	}
	*opt = TelnetOption(byte(aux.Value))
	return nil
}

// GetTelnetBanner attempts to negotiate the options and fetch the telnet banner over the given connection, reading at
// most maxReadSize bytes.
func GetTelnetBanner(logStruct *TelnetLog, conn net.Conn, maxReadSize int) (err error) {
	if err = NegotiateOptions(logStruct, conn); err != nil {
		return err
	}

	var bannerSlice []byte
	//grab banner
	buffer := make([]byte, READ_BUFFER_LENGTH)

	numBytes := len(buffer)
	rounds := int(math.Ceil(float64(maxReadSize) / READ_BUFFER_LENGTH))
	count := 0
	for numBytes != 0 && count < rounds && numBytes == READ_BUFFER_LENGTH {

		numBytes, err = conn.Read(buffer)
		// ignore timeout errors if there is already banner content
		if err, ok := err.(net.Error); ok && err.Timeout() {
			if len(logStruct.Banner) == 0 {
				return err
			}
			break
		}

		if err != nil && err != io.EOF {
			return err
		}

		if containsIAC(buffer) {
			continue
		}

		if count == rounds-1 {
			bannerSlice = append(bannerSlice, buffer[0:maxReadSize%READ_BUFFER_LENGTH]...)
		} else {
			bannerSlice = append(bannerSlice, buffer[0:numBytes]...)
		}
		count++
	}

	logStruct.Banner += string(bannerSlice)

	return nil
}

// NegotiateOptions attempts to negotiate the connection options over the given connection.
func NegotiateOptions(logStruct *TelnetLog, conn net.Conn) error {
	var readBuffer, retBuffer []byte
	var option, optionType, returnOptionType byte
	var iacIndex, firstUnreadIndex, numBytes, numDataBytes int
	var err error

	for finishedNegotiating := false; finishedNegotiating == false; {
		readBuffer = make([]byte, READ_BUFFER_LENGTH)
		retBuffer = nil
		numBytes, err = conn.Read(readBuffer)
		numDataBytes = numBytes

		if err != nil {
			return err
		}

		if numBytes == len(readBuffer) {
			return errors.New("Not enough buffer space for telnet options")
		}

		// Negotiate options

		for iacIndex = bytes.IndexByte(readBuffer, IAC); iacIndex != -1; iacIndex = bytes.IndexByte(readBuffer, IAC) {
			firstUnreadIndex = 0
			optionType = readBuffer[iacIndex+1]
			option = readBuffer[iacIndex+2]

			// ignore go ahead
			if optionType == GO_AHEAD {
				readBuffer = readBuffer[0:iacIndex]
				numBytes = iacIndex
				firstUnreadIndex = 0
				break
			}

			// record all offered options
			opt := TelnetOption(option)
			if optionType == WILL {
				logStruct.Will = append(logStruct.Will, opt)
			} else if optionType == DO {
				logStruct.Do = append(logStruct.Do, opt)
			} else if optionType == WONT {
				logStruct.Wont = append(logStruct.Wont, opt)
			} else if optionType == DONT {
				logStruct.Dont = append(logStruct.Dont, opt)
			}

			// reject all offered options
			if optionType == WILL || optionType == WONT {
				returnOptionType = DONT
			} else if optionType == DO || optionType == DONT {
				returnOptionType = WONT
			} else {
				return errors.New("Unsupported telnet IAC option type" + fmt.Sprintf("%d", optionType))
			}

			retBuffer = append(retBuffer, IAC)
			retBuffer = append(retBuffer, returnOptionType)
			retBuffer = append(retBuffer, option)

			firstUnreadIndex = iacIndex + IAC_CMD_LENGTH
			numDataBytes -= firstUnreadIndex
			readBuffer = readBuffer[firstUnreadIndex:]
		}

		if _, err = conn.Write(retBuffer); err != nil {
			return err
		}

		numIACBytes := numBytes - numDataBytes
		finishedNegotiating = numBytes != numIACBytes
	}

	// no more IAC commands, just read the resulting data
	if numDataBytes >= 0 {
		logStruct.Banner = string(readBuffer[0:numDataBytes])
	}

	return nil
}

func containsIAC(buffer []byte) bool {
	return bytes.IndexByte(buffer, IAC) != -1
}
