/*
* MIT License
*
* Copyright (c) 2017 stacktitan
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
 */

package gss

import (
	"encoding/asn1"
	"log"

	"github.com/zmap/zgrab2/lib/smb/encoder"
)

const SpnegoOid = "1.3.6.1.5.5.2"
const NtLmSSPMechTypeOid = "1.3.6.1.4.1.311.2.2.10"

const GssStateAcceptCompleted = 0
const GssStateAcceptIncomplete = 1
const GssStateReject = 2
const GssStateRequestMic = 3

type NegTokenInitData struct {
	MechTypes    []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags     asn1.BitString          `asn1:"explicit,optional,omitempty,tag:1"`
	MechToken    []byte                  `asn1:"explicit,optional,omitempty,tag:2"`
	MechTokenMIC []byte                  `asn1:"explicit,optional,omitempty,tag:3"`
}

type NegTokenInit struct {
	OID  asn1.ObjectIdentifier
	Data NegTokenInitData `asn1:"explicit"`
}

type NegTokenResp struct {
	State         asn1.Enumerated       `asn1:"explicit,optional,omitempty,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,omitempty,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,omitempty,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,omitempty,tag:3"`
}

// gsswrapped used to force ASN1 encoding to include explicit sequence tags
// Type does not fulfill the BinaryMarshallable interface and is used only as a
// helper to marshal a NegTokenResp
type gsswrapped struct{ G interface{} }

func NewNegTokenInit() (NegTokenInit, error) {
	oid, err := ObjectIDStrToInt(SpnegoOid)
	if err != nil {
		return NegTokenInit{}, err
	}
	ntlmoid, err := ObjectIDStrToInt(NtLmSSPMechTypeOid)
	if err != nil {
		return NegTokenInit{}, err
	}
	return NegTokenInit{
		OID: oid,
		Data: NegTokenInitData{
			MechTypes:    []asn1.ObjectIdentifier{ntlmoid},
			ReqFlags:     asn1.BitString{},
			MechToken:    []byte{},
			MechTokenMIC: []byte{},
		},
	}, nil
}

func NewNegTokenResp() (NegTokenResp, error) {
	return NegTokenResp{}, nil
}

func (n *NegTokenInit) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	buf, err := asn1.Marshal(*n)
	if err != nil {
		log.Panicln(err)
		return nil, err
	}

	// When marshalling struct, asn1 uses 30 (sequence) tag by default.
	// Override to set 60 (application) to remain consistent with GSS/SMB
	buf[0] = 0x60
	return buf, nil
}

func (n *NegTokenInit) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	data := NegTokenInit{}
	if _, err := asn1.UnmarshalWithParams(buf, &data, "application"); err != nil {
		return err
	}
	*n = data
	return nil
}

func (r *NegTokenResp) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	// Oddities in Go's ASN1 package vs SMB encoding mean we have to wrap our
	// struct in another struct to ensure proper tags and lengths are added
	// to encoded data
	wrapped := &gsswrapped{*r}
	return wrapped.MarshalBinary(meta)
}

func (r *NegTokenResp) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	data := NegTokenResp{}
	if _, err := asn1.UnmarshalWithParams(buf, &data, "explicit,tag:1"); err != nil {
		return err
	}
	*r = data
	return nil
}

func (g *gsswrapped) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	buf, err := asn1.Marshal(*g)
	if err != nil {
		return nil, err
	}
	buf[0] = 0xa1
	return buf, nil
}
