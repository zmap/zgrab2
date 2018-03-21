package bacnet

import "bytes"

type VLC struct {
	Type     byte
	Function byte
	Length   uint16
}

type NPDU struct {
	Version byte
	Control byte
}

type SegmentParameters struct {
	raw byte
	set bool
}

type APDU struct {
	TypeAndFlags byte              `json:"type_and_flags"`
	SegmentSizes SegmentParameters `json:"segment_sizes"`
	InvokeID     byte              `json:"invoke_id"`
	ServerChoice byte              `json:"server_choice"`
}

type Frame struct {
	VLC     *VLC        `json:"vlc,omitempty"`
	NPDU    *NPDU       `json:"npdu,omitempty"`
	APDU    *APDU       `json:"apdu,omitempty"`
	Payload interface{} `json:"payload,omitempty"`
}

const vlcLength = 4

// Marshal encodes a VLC header to binary
func (vlc *VLC) Marshal() ([]byte, error) {
	out := make([]byte, vlcLength)
	out[0] = vlc.Type
	out[1] = vlc.Function
	out[2] = byte(vlc.Length >> 8)
	out[3] = byte(vlc.Length)
	return out, nil
}

// Unmarshal decodes a VLC header from binary
func (vlc *VLC) Unmarshal(b []byte) ([]byte, error) {
	if len(b) < vlcLength {
		return b, errBACNetPacketTooShort
	}
	if b[0] != 0x81 {
		return b, errNotBACNet
	}
	vlc.Type = b[0]
	vlc.Function = b[1]
	vlc.Length = (uint16(b[2]) << 8) + uint16(b[3])
	rb := b[vlcLength:]
	return rb, nil
}

const npduLength = 2

// Marshal encodes an NPDU header to binary
func (npdu *NPDU) Marshal() ([]byte, error) {
	b := make([]byte, npduLength)
	b[0] = npdu.Version
	b[1] = npdu.Control
	return b, nil
}

// Unmarshal decodes an NPDU header from binary
func (npdu *NPDU) Unmarshal(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return b, errBACNetPacketTooShort
	}
	npdu.Version = b[0]
	npdu.Control = b[1]
	return b[2:], nil
}

// Marshal encodes a full APDU to binary
func (apdu *APDU) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(apdu.TypeAndFlags)
	if apdu.SegmentSizes.set {
		buf.WriteByte(apdu.SegmentSizes.raw)
	}
	buf.WriteByte(apdu.InvokeID)
	buf.WriteByte(apdu.ServerChoice)
	return buf.Bytes(), nil
}

// Unmarshal decodes a full APDU from binary
func (apdu *APDU) Unmarshal(b []byte) (out []byte, err error) {
	buf := bytes.NewBuffer(b)
	if apdu.TypeAndFlags, err = buf.ReadByte(); err != nil {
		return b, errBACNetPacketTooShort
	}
	if apdu.SegmentSizes.set {
		if apdu.SegmentSizes.raw, err = buf.ReadByte(); err != nil {
			return b, errBACNetPacketTooShort
		}
	}
	if apdu.InvokeID, err = buf.ReadByte(); err != nil {
		return b, errBACNetPacketTooShort
	}
	if apdu.ServerChoice, err = buf.ReadByte(); err != nil {
		return b, errBACNetPacketTooShort
	}
	bytesRead := len(b) - buf.Len()
	return b[bytesRead:], nil
}
