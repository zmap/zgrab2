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

func getParse(b byte) func(*AttrValue) {
	switch {
// Out-of-Band Values
//	// unsupported
//	case b == 0x10:
//
//	// unknown
//	case b == 0x12:
//
//	// no-value
//	case b == 0x13:


// Integer Types
	// Integer
	case b == 0x21:
		return func(val *AttrValue) {
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
		}
	// Boolean
	case b == 0x22:
		return func(val *AttrValue) {
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
		}
	// Enum
	case b == 0x23:
		return func(val *AttrValue) {
			// TODO: Implement
		}

// octetString Types
	// octetString
	case b == 0x30:
		return func(val *AttrValue) {
			// TODO: Implement
		}
	// dateTime
	case b == 0x31:
		return func(val *AttrValue) {
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
		}
	// resolution
	case b == 0x32:
		return func(val *AttrValue) {
			// TODO: Implement
		}
	// rangeOfInteger
	case b == 0x33:
		return func(val *AttrValue) {
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
		}
	// begCollection
	case b == 0x34:
		return func(val *AttrValue) {
			// TODO: Implement
		}
	// textWithLanguage
	case b == 0x35:
		return func(val *AttrValue) {
			// TODO: Implement
		}
	// nameWithLanguage
	case b == 0x36:
		return func(val *AttrValue) {
			// TODO: Implement
		}
	// endCollection
	case b == 0x37:
		return func(val *AttrValue) {
			// TODO: Implement
		}

// String Tags
// [0x40, 0x5f] are reserved for character-string data types, assigned or otherwise
// TODO: Ensure that any cases that require special encoding consideration handle that
	case b & 0xf0 == 0x40 || b & 0xf0 == 0x50:
		return func(val *AttrValue) {
			s := string(val.Bytes)
			switch b {
			// textWithoutLanguage
			case 0x41:
				val.Text = s
			// nameWithoutLanguage
			case 0x42:
				val.Name = s
			// keyword
			case 0x44:
				val.Keyword = s
			// uri
			case 0x45:
				val.URI = s
			// uriScheme
			case 0x46:
				val.Scheme = s
			// charset
			case 0x47:
				val.Charset = s
			// naturalLanguage
			case 0x48:
				val.Lang = s
			// mimeMediaType
			case 0x49:
				val.MimeType = s
			// memberAttrName
			case 0x4a:
				val.MemberName = s
			}
		}
	default:
		return nil
	}
}