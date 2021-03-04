package encoder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type BinaryMarshallable interface {
	MarshalBinary(*Metadata) ([]byte, error)
	UnmarshalBinary([]byte, *Metadata) error
}

type Metadata struct {
	Tags       *TagMap
	Lens       map[string]uint64
	Offsets    map[string]uint64
	Parent     interface{}
	ParentBuf  []byte
	CurrOffset uint64
	CurrField  string
}

type TagMap struct {
	m   map[string]interface{}
	has map[string]bool
}

func (t TagMap) Has(key string) bool {
	return t.has[key]
}

func (t TagMap) Set(key string, val interface{}) {
	t.m[key] = val
	t.has[key] = true
}

func (t TagMap) Get(key string) interface{} {
	return t.m[key]
}

func (t TagMap) GetInt(key string) (int, error) {
	if !t.Has(key) {
		return 0, errors.New("Key does not exist in tag")
	}
	return t.Get(key).(int), nil
}

func (t TagMap) GetString(key string) (string, error) {
	if !t.Has(key) {
		return "", errors.New("Key does not exist in tag")
	}
	return t.Get(key).(string), nil
}

func parseTags(sf reflect.StructField) (*TagMap, error) {
	ret := &TagMap{
		m:   make(map[string]interface{}),
		has: make(map[string]bool),
	}
	tag := sf.Tag.Get("smb")
	smbTags := strings.Split(tag, ",")
	for _, smbTag := range smbTags {
		tokens := strings.Split(smbTag, ":")
		switch tokens[0] {
		case "len", "offset", "count":
			if len(tokens) != 2 {
				return nil, errors.New("Missing required tag data. Expecting key:val")
			}
			ret.Set(tokens[0], tokens[1])
		case "fixed":
			if len(tokens) != 2 {
				return nil, errors.New("Missing required tag data. Expecting key:val")
			}
			i, err := strconv.Atoi(tokens[1])
			if err != nil {
				return nil, err
			}
			ret.Set(tokens[0], i)
		case "asn1":
			ret.Set(tokens[0], true)
		}
	}

	return ret, nil
}

func getOffsetByFieldName(fieldName string, meta *Metadata) (uint64, error) {
	if meta == nil || meta.Tags == nil || meta.Parent == nil || meta.Lens == nil {
		return 0, errors.New("Cannot determine field offset. Missing required metadata")
	}
	var ret uint64
	var found bool
	parentvf := reflect.Indirect(reflect.ValueOf(meta.Parent))
	// To determine offset, we loop through all fields of the struct, summing lengths of previous elements
	// until we reach our field
	for i := 0; i < parentvf.NumField(); i++ {
		tf := parentvf.Type().Field(i)
		if tf.Name == fieldName {
			found = true
			break
		}
		if l, ok := meta.Lens[tf.Name]; ok {
			// Length of field is in cache
			ret += l
		} else {
			// Not in cache. Must marshal field to determine length. Add to cache after
			buf, err := Marshal(parentvf.Field(i).Interface())
			if err != nil {
				return 0, err
			}
			l := uint64(len(buf))
			meta.Lens[tf.Name] = l
			ret += l
		}
	}
	if !found {
		return 0, errors.New("Cannot find field name within struct: " + fieldName)
	}
	return ret, nil
}

func getFieldLengthByName(fieldName string, meta *Metadata) (uint64, error) {
	var ret uint64
	if meta == nil || meta.Tags == nil || meta.Parent == nil || meta.Lens == nil {
		return 0, errors.New("Cannot determine field length. Missing required metadata")
	}

	// Check if length is stored in field length cache
	if val, ok := meta.Lens[fieldName]; ok {
		return uint64(val), nil
	}

	parentvf := reflect.Indirect(reflect.ValueOf(meta.Parent))

	field := parentvf.FieldByName(fieldName)
	if !field.IsValid() {
		return 0, errors.New("Invalid field. Cannot determine length.")
	}

	bm, ok := field.Interface().(BinaryMarshallable)
	if ok {
		// Custom marshallable interface found.
		buf, err := bm.(BinaryMarshallable).MarshalBinary(meta)
		if err != nil {
			return 0, err
		}
		return uint64(len(buf)), nil
	}

	if field.Kind() == reflect.Ptr {
		field = field.Elem()
	}

	switch field.Kind() {
	case reflect.Struct:
		buf, err := Marshal(field.Interface())
		if err != nil {
			return 0, err
		}
		ret = uint64(len(buf))
	case reflect.Interface:
		return 0, errors.New("Interface length calculation not implemented")
	case reflect.Slice, reflect.Array:
		switch field.Type().Elem().Kind() {
		case reflect.Uint8:
			ret = uint64(len(field.Interface().([]byte)))
		default:
			return 0, errors.New("Cannot calculate the length of unknown slice type for " + fieldName)
		}
	case reflect.Uint8:
		ret = uint64(binary.Size(field.Interface().(uint8)))
	case reflect.Uint16:
		ret = uint64(binary.Size(field.Interface().(uint16)))
	case reflect.Uint32:
		ret = uint64(binary.Size(field.Interface().(uint32)))
	case reflect.Uint64:
		ret = uint64(binary.Size(field.Interface().(uint64)))
	default:
		return 0, errors.New("Cannot calculate the length of unknown kind for field " + fieldName)
	}
	meta.Lens[fieldName] = ret
	return ret, nil
}

func Marshal(v interface{}) ([]byte, error) {
	return marshal(v, nil)
}

func marshal(v interface{}, meta *Metadata) ([]byte, error) {
	var ret []byte
	tf := reflect.TypeOf(v)
	vf := reflect.ValueOf(v)

	bm, ok := v.(BinaryMarshallable)
	if ok {
		// Custom marshallable interface found.
		buf, err := bm.MarshalBinary(meta)
		if err != nil {
			return nil, err
		}
		return buf, nil
	}

	if tf.Kind() == reflect.Ptr {
		vf = reflect.Indirect(reflect.ValueOf(v))
		tf = vf.Type()
	}

	w := bytes.NewBuffer(ret)
	switch tf.Kind() {
	case reflect.Struct:
		m := &Metadata{
			Tags:   &TagMap{},
			Lens:   make(map[string]uint64),
			Parent: v,
		}
		for j := 0; j < vf.NumField(); j++ {
			tags, err := parseTags(tf.Field(j))
			if err != nil {
				return nil, err
			}
			m.Tags = tags
			buf, err := marshal(vf.Field(j).Interface(), m)
			if err != nil {
				return nil, err
			}
			m.Lens[tf.Field(j).Name] = uint64(len(buf))
			if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
				return nil, err
			}
		}
	case reflect.Slice, reflect.Array:
		switch tf.Elem().Kind() {
		case reflect.Uint8:
			if err := binary.Write(w, binary.LittleEndian, v.([]uint8)); err != nil {
				return nil, err
			}
		case reflect.Uint16:
			if err := binary.Write(w, binary.LittleEndian, v.([]uint16)); err != nil {
				return nil, err
			}
		}
	case reflect.Uint8:
		if err := binary.Write(w, binary.LittleEndian, vf.Interface().(uint8)); err != nil {
			return nil, err
		}
	case reflect.Uint16:
		data := vf.Interface().(uint16)
		if meta != nil && meta.Tags.Has("len") {
			fieldName, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			l, err := getFieldLengthByName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint16(l)
		}
		if meta != nil && meta.Tags.Has("offset") {
			fieldName, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			l, err := getOffsetByFieldName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint16(l)
		}
		if err := binary.Write(w, binary.LittleEndian, data); err != nil {
			return nil, err
		}
	case reflect.Uint32:
		data := vf.Interface().(uint32)
		if meta != nil && meta.Tags.Has("len") {
			fieldName, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			l, err := getFieldLengthByName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint32(l)
		}
		if meta != nil && meta.Tags.Has("offset") {
			fieldName, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			l, err := getOffsetByFieldName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint32(l)
		}
		if err := binary.Write(w, binary.LittleEndian, data); err != nil {
			return nil, err
		}
	case reflect.Uint64:
		if err := binary.Write(w, binary.LittleEndian, vf.Interface().(uint64)); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New(fmt.Sprintf("Marshal not implemented for kind: %s", tf.Kind()))
	}
	return w.Bytes(), nil
}

func unmarshal(buf []byte, v interface{}, meta *Metadata) (interface{}, error) {
	tf := reflect.TypeOf(v)
	vf := reflect.ValueOf(v)

	bm, ok := v.(BinaryMarshallable)
	if ok {
		// Custom marshallable interface found.
		if err := bm.UnmarshalBinary(buf, meta); err != nil {
			return nil, err
		}
		return bm, nil
	}

	if tf.Kind() == reflect.Ptr {
		vf = reflect.ValueOf(v).Elem()
		tf = vf.Type()
	}

	if meta == nil {
		meta = &Metadata{
			Tags:       &TagMap{},
			Lens:       make(map[string]uint64),
			Parent:     v,
			ParentBuf:  buf,
			Offsets:    make(map[string]uint64),
			CurrOffset: 0,
		}
	}

	r := bytes.NewBuffer(buf)
	switch tf.Kind() {
	case reflect.Struct:
		m := &Metadata{
			Tags:       &TagMap{},
			Lens:       make(map[string]uint64),
			Parent:     v,
			ParentBuf:  buf,
			Offsets:    make(map[string]uint64),
			CurrOffset: 0,
		}
		for i := 0; i < tf.NumField(); i++ {
			m.CurrField = tf.Field(i).Name
			tags, err := parseTags(tf.Field(i))
			if err != nil {
				return nil, err
			}
			m.Tags = tags
			var data interface{}
			switch tf.Field(i).Type.Kind() {
			case reflect.Struct:
				data, err = unmarshal(buf[m.CurrOffset:], vf.Field(i).Addr().Interface(), m)
			default:
				data, err = unmarshal(buf[m.CurrOffset:], vf.Field(i).Interface(), m)
			}
			if err != nil {
				return nil, err
			}
			vf.Field(i).Set(reflect.ValueOf(data))
		}
		v = reflect.Indirect(reflect.ValueOf(v)).Interface()
		meta.CurrOffset += m.CurrOffset
		return v, nil
	case reflect.Uint8:
		var ret uint8
		if err := binary.Read(r, binary.LittleEndian, &ret); err != nil {
			return nil, err
		}
		meta.CurrOffset += uint64(binary.Size(ret))
		return ret, nil
	case reflect.Uint16:
		var ret uint16
		if err := binary.Read(r, binary.LittleEndian, &ret); err != nil {
			return nil, err
		}
		if meta.Tags.Has("len") {
			ref, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			meta.Lens[ref] = uint64(ret)
		}
		meta.CurrOffset += uint64(binary.Size(ret))
		return ret, nil
	case reflect.Uint32:
		var ret uint32
		if err := binary.Read(r, binary.LittleEndian, &ret); err != nil {
			return nil, err
		}
		if meta.Tags.Has("offset") {
			ref, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			meta.Offsets[ref] = uint64(ret)
		}
		meta.CurrOffset += uint64(binary.Size(ret))
		return ret, nil
	case reflect.Uint64:
		var ret uint64
		if err := binary.Read(r, binary.LittleEndian, &ret); err != nil {
			return nil, err
		}
		meta.CurrOffset += uint64(binary.Size(ret))
		return ret, nil
	case reflect.Slice, reflect.Array:
		switch tf.Elem().Kind() {
		case reflect.Uint8:
			var l, o int
			var err error
			if meta.Tags.Has("fixed") {
				if l, err = meta.Tags.GetInt("fixed"); err != nil {
					return nil, err
				}
				// Fixed length fields advance current offset
				meta.CurrOffset += uint64(l)
			} else {
				if val, ok := meta.Lens[meta.CurrField]; ok {
					l = int(val)
				} else {
					return nil, errors.New("Variable length field missing length reference in struct: " + meta.CurrField)
				}
				if val, ok := meta.Offsets[meta.CurrField]; ok {
					o = int(val)
				} else {
					// No offset found in map. Use current offset
					o = int(meta.CurrOffset)
				}
				// Prevent searching past the end of the buffer for variable data
				if o+l >= len(meta.ParentBuf) {
					return nil, errors.New(fmt.Sprintf("field '%s' wants %d bytes but only %d bytes remain.", meta.CurrField, l, len(meta.ParentBuf)-o))
				}
				// Variable length data is relative to parent/outer struct. Reset reader to point to beginning of data
				r = bytes.NewBuffer(meta.ParentBuf[o : o+l])
				// Variable length data fields do NOT advance current offset.
			}
			data := make([]byte, l)
			if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
				return nil, err
			}
			return data, nil
		case reflect.Uint16:
			return errors.New("Unmarshal not implemented for slice kind:" + tf.Kind().String()), nil
		}
	default:
		return errors.New("Unmarshal not implemented for kind:" + tf.Kind().String()), nil
	}

	return nil, nil

}

func Unmarshal(buf []byte, v interface{}) error {
	_, err := unmarshal(buf, v, nil)
	return err
}
