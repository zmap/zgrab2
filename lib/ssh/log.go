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

package ssh

// HandshakeLog contains detailed information about each step of the
// SSH handshake, and can be encoded to JSON.
type HandshakeLog struct {
	Banner             string       `json:"banner,omitempty"`
	ServerID           *EndpointId  `json:"server_id,omitempty"`
	ClientID           *EndpointId  `json:"client_id,omitempty"`
	ServerKex          *KexInitMsg  `json:"server_key_exchange,omitempty"`
	ClientKex          *KexInitMsg  `json:"client_key_exchange,omitempty"`
	AlgorithmSelection *Algorithms  `json:"algorithm_selection,omitempty"`
	DHKeyExchange      kexAlgorithm `json:"key_exchange,omitempty"`
	UserAuth           []string     `json:"userauth,omitempty"`
	Crypto             *kexResult   `json:"crypto,omitempty"`
}

type EndpointId struct {
	Raw             string `json:"raw,omitempty"`
	ProtoVersion    string `json:"version,omitempty"`
	SoftwareVersion string `json:"software,omitempty"`
	Comment         string `json:"comment,omitempty"`
}
