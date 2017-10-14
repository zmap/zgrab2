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

package keys

import (
	"encoding/json"
	"math/big"
	"testing"

	. "gopkg.in/check.v1"
)

func TestDHE(t *testing.T) { TestingT(t) }

// from testdata/test1024dh.pem
var test1024Prime = []byte{0x00, 0xAE, 0x6A, 0xFA, 0xE1, 0x1D, 0x60, 0x76, 0x64, 0x56, 0x17, 0x01, 0x55, 0x14, 0xF0, 0x38, 0x71, 0xA0, 0x9E, 0xA2, 0x0C, 0x02, 0x03, 0x0E, 0x35, 0xC7, 0xD4, 0x2D, 0x32, 0x6A, 0x61, 0x24, 0x72, 0xDE, 0x64, 0x53, 0xB7, 0xEA, 0xB4, 0x89, 0x51, 0xF9, 0x2E, 0x24, 0x6D, 0x1B, 0x18, 0xC4, 0xAA, 0xB5, 0x5C, 0x0C, 0x90, 0xEC, 0xF9, 0xA0, 0x3D, 0xD8, 0x09, 0xEF, 0x85, 0x6E, 0x74, 0xC3, 0xC2, 0x13, 0x42, 0x17, 0xAA, 0x68, 0x79, 0xFD, 0x9C, 0xB5, 0xED, 0x6E, 0x3A, 0x31, 0xE7, 0x86, 0xCA, 0x08, 0xBC, 0xE6, 0xE7, 0x65, 0xCB, 0xB2, 0x08, 0xEA, 0x8C, 0x21, 0x3C, 0xE6, 0x0E, 0x66, 0xDD, 0x5E, 0x7D, 0x04, 0x57, 0xD8, 0xE4, 0xB3, 0x0B, 0xEF, 0x40, 0x71, 0x0C, 0xA1, 0xE2, 0x12, 0x75, 0x80, 0x92, 0x85, 0x22, 0x6E, 0xCF, 0x37, 0x43, 0x48, 0x27, 0x4C, 0x21, 0x22, 0xE6, 0xC7, 0xE3}
var testGenerator = []byte{0x02}

type DHESuite struct {
	prime1024 *cryptoParameter
	generator *cryptoParameter
	param1024 *DHParams
}

var _ = Suite(&DHESuite{})

func (s *DHESuite) SetUpTest(c *C) {
	s.prime1024 = new(cryptoParameter)
	s.prime1024.Int = new(big.Int)
	s.prime1024.SetBytes(test1024Prime)
	s.generator = new(cryptoParameter)
	s.generator.Int = new(big.Int)
	s.generator.SetBytes(testGenerator)
	s.param1024 = new(DHParams)
	s.param1024.Prime = s.prime1024.Int
	s.param1024.Generator = s.generator.Int
}

func (s *DHESuite) TestEncodeDecodeCryptoParameter(c *C) {
	b, err := json.Marshal(s.prime1024)
	c.Assert(err, IsNil)
	c.Assert(b, NotNil)
	var dec cryptoParameter
	err = json.Unmarshal(b, &dec)
	c.Assert(err, IsNil)
	cmp := dec.Cmp(s.prime1024.Int)
	c.Check(cmp, Equals, 0)
}

func (s *DHESuite) TestEncodeDecodeDHParams(c *C) {
	b, err := json.Marshal(s.param1024)
	c.Assert(err, IsNil)
	c.Assert(b, NotNil)
	var dec DHParams
	err = json.Unmarshal(b, &dec)
	c.Assert(err, IsNil)
	c.Check(dec.Prime.Cmp(s.param1024.Prime), Equals, 0)
	c.Check(dec.Generator.Cmp(s.param1024.Generator), Equals, 0)
}
