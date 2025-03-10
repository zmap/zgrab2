package bacnet

import (
	. "gopkg.in/check.v1"
)

type ObjectsSuite struct {
}

var _ = Suite(&ObjectsSuite{})

func (s *ObjectsSuite) TestMarshalUnmarshalReadProperty(c *C) {
	rp := ReadProperty{
		Object:   OID_ANY,
		Property: PID_OID,
	}
	b, err := rp.Marshal()
	c.Assert(err, IsNil)
	dec := new(ReadProperty)
	b, err = dec.Unmarshal(b)
	c.Assert(err, IsNil)
	c.Check(len(b), Equals, 0)
	c.Check(dec, DeepEquals, &rp)
}
