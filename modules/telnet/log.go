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

// TelnetLog is the output of the telnet grab.
type TelnetLog struct {
	// Banner is the telnet banner returned by the server.
	Banner string `json:"banner,omitempty"`

	// Will is the list of options that the server says that it will use.
	Will []TelnetOption `json:"will,omitempty"`

	// Do is the list of options that the server requests that the client use.
	Do []TelnetOption `json:"do,omitempty"`

	// Wont is the list of options that the server says it will *not* use.
	Wont []TelnetOption `json:"wont,omitempty"`

	// Dont is the list of options that the server requests the client *not* use.
	Dont []TelnetOption `json:"dont,omitempty"`
}

// isTelnet checks if this struct represents having actually detected a Telnet service.
func (log *TelnetLog) isTelnet() bool {
	return len(log.Will) > 0 || len(log.Do) > 0 || len(log.Wont) > 0 || len(log.Dont) > 0
}

// getResult returns the log itself if it represents a Telnet service, otherwise, it returns nil.
func (log *TelnetLog) getResult() *TelnetLog {
	if log == nil {
		return nil
	}
	if log.isTelnet() {
		return log
	}
	return nil
}
