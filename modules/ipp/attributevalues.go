package ipp

import (
	"encoding/binary"
	"bytes"
	"time"

	log "github.com/sirupsen/logrus"
)

type IPPTime struct {
	Year uint16
	Month byte
	Day byte
	Hour byte
	Minutes byte
	Seconds byte
	Deciseconds byte
	DirectionFromUTC byte
	HoursFromUTC byte
	MinutesFromUTC byte
}

type RangeOfInteger struct {
	Min int32 `json:"min"`
	Max int32 `json:"max"`
}

var Parse = map[byte]func(*AttrValue) {
// Out-of-Band Values
	/*0x10:
	0x12:
	0x13:*/

// Integer Tags
	// integer
	0x21: func(val *AttrValue) {
		buf := bytes.NewBuffer(val.Bytes)
		var i int32
		if err := binary.Read(buf, binary.BigEndian, &i); err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"data": val.Bytes,
			}).Debug("Failed to interpret data with error.")
			return
		}
		val.Integer = &i
	},
	// boolean
	0x22: func(val *AttrValue) {
		if len(val.Bytes) == 1 {
			var truth bool
			switch val.Bytes[0] {
			case 0x00:
				truth = false
			case 0x01:
				truth = true
			}
			val.Boolean = &truth
		}
	},
	// enum
	0x23: func(val *AttrValue) {
		// TODO: Implement
	},

// octetString Tags
	// octetString
	0x30: func(val *AttrValue) {
		// TODO: Seems like doing nothing for octetStrings is more appropriate, since they're analogous to the raw byte string
		// TODO: Implement
	},
	// dateTime
	0x31: func(val *AttrValue) {
		buf := bytes.NewBuffer(val.Bytes)
		t := &IPPTime{}
		if err := binary.Read(buf, binary.BigEndian, t); err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"data": val.Bytes,
			}).Debug("Failed to interpret data with error.")
			return
		}
		// Seconds East of UTC
		// + -> East
		// - -> West
		secondsEast := int(t.DirectionFromUTC) * 60 * (int(t.MinutesFromUTC) + (60 * int(t.HoursFromUTC)))
		loc := time.FixedZone("", secondsEast)
		// TODO: Determine whether to convert to UTC, since the end result will become UTC regardless in python
		date := time.Date(int(t.Year), time.Month(t.Month), int(t.Day), int(t.Hour), int(t.Minutes), int(t.Seconds), int(t.Deciseconds) * 1e8, loc).UTC()
		val.Date = &date
	},
	// resolution
	0x32: func(val *AttrValue) {
		// TODO: Implement
	},
	// rangeOfInteger
	0x33: func(val *AttrValue) {
		buf := bytes.NewBuffer(val.Bytes)
		r := &RangeOfInteger{}
		if err := binary.Read(buf, binary.BigEndian, r); err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"data": val.Bytes,
			}).Debug("Failed to interpret data with error.")
			return
		}
		val.Range = r
	},
	// begCollection
	0x34: func(val *AttrValue) {
		// TODO: Implement
	},
	// textWithLanguage
	0x35: func(val *AttrValue) {
		// TODO: Implement
	},
	// nameWithLanguage
	0x36: func(val *AttrValue) {
		// TODO: Implement
	},
	// endCollection
	0x37: func(val *AttrValue) {
		// TODO: Implement
	},

// String Tags
// TODO: Consolidate all string parsers into one function? Unless charset affects things.
// TODO: Refactor s.t. if statements differentiate behavior, since these can all collapse into one handler
// TODO: But particular comments might be worth separating them out
	// TODO: This should be dependent upon charset somehow??
	// textWithoutLanguage
	0x41: func(val *AttrValue) {
		// TODO: Implement

	},
	// nameWithoutLanguage
	0x42: func(val *AttrValue) {
		// TODO: Implement
	},
	// keyword
	0x44: func(val *AttrValue) {
		// TODO: Maybe provide additional mappings from keywords to implementation-specific
		//       choices for those keywords? Probably not.
		// TODO: Implement
	},
	// uri
	0x45: func(val *AttrValue) {
		// Valid URI's can only contain certain ascii characters, so there shouldn't be charset issues
		// Source: RFC
		// TODO: Max size of 1023 octets, but that's probably automatic by taking in that data
		// TODO: Is there any problem with character set, encoding, or case-sensitivity
		val.URI = string(val.Bytes)
	},
	// uriScheme
	0x46: func(val *AttrValue) {
		// Max size of 63 octets
		// TODO: Refer back to 0x45's function, since they should be the same
		val.Scheme = string(val.Bytes)
	},
	// charset
	0x47: func(val *AttrValue) {
		// Max size of 63 octets
		val.Charset = string(val.Bytes)
	},
	// naturalLanguage
	0x48: func(val *AttrValue) {
		// Restricted to A-Z,a-z,0-9,-, so there shouldn't be charset conflicts
		// Source: RFC 5646 Section 7 https://tools.ietf.org/html/rfc5646#section-7
		// TODO: Match legacy identifiers with modern equivalents? Doesn't seem to be necessary.
		val.Lang = string(val.Bytes)
	},
	// mimeMediaType
	0x49: func(val *AttrValue) {
		// TODO: Implement
	},
	// memberAttrName
	0x4a: func(val *AttrValue) {
		// TODO: Implement
	},
}