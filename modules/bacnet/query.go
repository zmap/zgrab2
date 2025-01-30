package bacnet

import "bytes"

type ReadPropertyRequest struct {
	NPDU      NPDU         `json:"npdu"`
	APDU      APDU         `json:"apdu"`
	Selection ReadProperty `json:"read_property"`
}

func (rp *ReadPropertyRequest) Marshal() (out []byte, err error) {
	buf := new(bytes.Buffer)
	var b []byte
	if b, err = rp.NPDU.Marshal(); err != nil {
		return
	}
	buf.Write(b)
	if b, err = rp.APDU.Marshal(); err != nil {
		return
	}
	buf.Write(b)
	if b, err = rp.Selection.Marshal(); err != nil {
		return
	}
	buf.Write(b)
	return buf.Bytes(), nil
}

func NewReadPropertyRequest(oid ObjectID, pid PropertyID) *ReadPropertyRequest {
	req := new(ReadPropertyRequest)
	req.NPDU.Version = NPDU_VERSION_ASHRAE_135_1995
	req.NPDU.Control |= NPDU_FLAG_EXPECTING_RESPONSE
	req.APDU.TypeAndFlags = 0
	req.APDU.SegmentSizes.set = true
	req.APDU.SegmentSizes.raw = 0x05
	req.APDU.InvokeID = 1
	req.APDU.ServerChoice = SERVER_CHOICE_READ_PROPERTY
	req.Selection.Object = oid
	req.Selection.Property = pid
	return req
}
