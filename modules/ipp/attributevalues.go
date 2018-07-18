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
		// TODO: Determine whether to convert to UTC, since
		date := time.Date(int(t.Year), time.Month(t.Month), int(t.Day), int(t.Hour), int(t.Minutes), int(t.Seconds), int(t.Deciseconds) * 1e8, loc).UTC()
		val.Date = &date
	},
	// resolution
	0x32: func(val *AttrValue) {
		// TODO: Implement
	},
	// rangeOfInteger
	0x33: func(val *AttrValue) {
		// TODO: Implement
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
		// TODO: Implement
	},
	// uri
	0x45: func(val *AttrValue) {
		// TODO: Implement
	},
	// uriScheme
	0x46: func(val *AttrValue) {
		// TODO: Implement
	},
	// charset
	0x47: func(val *AttrValue) {
		// TODO: Implement
	},
	// naturalLanguage
	0x48: func(val *AttrValue) {
		// TODO: Implement
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