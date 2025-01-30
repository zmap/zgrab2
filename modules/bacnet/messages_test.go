package bacnet

import (
	"encoding/binary"
	"testing"

	. "gopkg.in/check.v1"
)

func TestMessages(t *testing.T) { TestingT(t) }

type VLCSuite struct {
}

type NPDUSuite struct {
}

type APDUSuite struct {
}

var _ = Suite(&VLCSuite{})
var _ = Suite(&NPDUSuite{})
var _ = Suite(&APDUSuite{})

func (s *VLCSuite) TestMarshalUnmarshalVLC(c *C) {
	vlc := VLC{
		Type:     VLC_TYPE_IP,
		Function: VLC_FUNCTION_UNICAST_NPDU,
		Length:   300,
	}
	b, e := vlc.Marshal()
	c.Assert(e, IsNil)
	c.Assert(b, NotNil)
	encodedLength := binary.BigEndian.Uint16(b[2:])
	c.Check(encodedLength, Equals, vlc.Length)
	dec := VLC{}
	b, err := dec.Unmarshal(b)
	c.Assert(err, IsNil)
	c.Check(len(b), Equals, 0)
}

func (s *VLCSuite) TestUnmarshalShortVLC(c *C) {
	b := make([]byte, vlcLength-1)
	v := VLC{}
	leftovers, err := v.Unmarshal(b)
	c.Check(leftovers, DeepEquals, b)
	c.Check(err, NotNil)
	c.Check(err, Equals, errBACNetPacketTooShort)
}

func (s *NPDUSuite) TestMarshalUnmarshalNPDU(c *C) {
	npdu := NPDU{
		Version: NPDU_VERSION_ASHRAE_135_1995,
		Control: 0x4,
	}
	b, e := npdu.Marshal()
	c.Assert(e, IsNil)
	c.Assert(b, NotNil)
	c.Check(len(b), Equals, 2)
	dec := NPDU{}
	leftovers, err := dec.Unmarshal(b)
	c.Check(len(leftovers), Equals, 0)
	c.Assert(err, IsNil)
	c.Check(dec, Equals, npdu)
}

func (s *NPDUSuite) TestMarshalUnmarshalShortNPDU(c *C) {
	b := make([]byte, npduLength-1)
	v := VLC{}
	leftovers, err := v.Unmarshal(b)
	c.Check(leftovers, DeepEquals, b)
	c.Check(err, Equals, errBACNetPacketTooShort)
}

func (s *APDUSuite) TestMarshalUnmarshalAPDU(c *C) {
	apdu := APDU{
		TypeAndFlags: 0x30,
		InvokeID:     1,
		ServerChoice: SERVER_CHOICE_READ_PROPERTY,
	}
	b, err := apdu.Marshal()
	c.Assert(err, IsNil)
	dec := new(APDU)
	b, err = dec.Unmarshal(b)
	c.Assert(err, IsNil)
	c.Check(dec, DeepEquals, &apdu)
	c.Check(len(b), Equals, 0)
}
