package drda

import (
	"encoding/hex"
	"testing"
)

func FuzzParseEXCSATRD(f *testing.F) {
	// A well-formed EXCSATRD reply captured from a real IBM DB2 11.1 server.
	realReply, _ := hex.DecodeString(
		"0066d0030001006014430024115ec4c2f240404040408482f2a2a8a28340f2c4" +
			"f9f4c3f2c2f46cc6c5c46ce8f0f0001814041403000724070008240f00081440" +
			"000814740008000d1147d8c4c2f261d5e3f6f40007116dc4c2f2000c115ae2d8d3" +
			"f1f1f0f1f3")
	f.Add(realReply)

	// A minimal, valid EXCSATRD produced by our own builder logic.
	f.Add(makeEXCSATRD(
		makeParam(cpSRVCLSNM, asciiToEBCDIC("QDB2/NT64")),
		makeParam(cpSRVRLSLV, asciiToEBCDIC("SQL11013")),
	))

	// Degenerate / adversarial seeds: too short, bad magic, lying lengths.
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x0a})
	f.Add([]byte{0x00, 0x0a, 0xd0, 0x03, 0x00, 0x01, 0x00, 0x04, 0x14, 0x43})
	// Length prefix claims more than the buffer holds.
	f.Add([]byte{0xff, 0xff, 0xd0, 0x03, 0x00, 0x01, 0x00, 0x60, 0x14, 0x43})
	// A parameter whose length overruns the DDM.
	f.Add([]byte{0x00, 0x0e, 0xd0, 0x03, 0x00, 0x01, 0x00, 0x08, 0x14, 0x43, 0xff, 0xff, 0x11, 0x47})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic or read out of bounds on arbitrary input.
		attrs, ok := parseEXCSATRD(data)
		if ok && attrs != nil {
			// Exercise the downstream decode path on any parsed attributes.
			_ = versionFromReleaseLevel(attrs.releaseLevel)
		}
	})
}
