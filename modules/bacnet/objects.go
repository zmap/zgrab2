package bacnet

import (
	"bytes"
	"encoding/binary"
)

type ObjectID uint32

const (
	OID_ANY ObjectID = 0x023fffff
)

type PropertyID byte

const (
	PID_OID                           PropertyID = 75
	PID_VENDOR_NUMBER                 PropertyID = 0x78
	PID_VENDOR_NAME                   PropertyID = 0x79
	PID_FIRMWARE_REVISION             PropertyID = 0x2c
	PID_APPLICATION_SOFTWARE_REVISION PropertyID = 0x0c
	PID_OBJECT_NAME                   PropertyID = 0x4d
	PID_MODEL_NAME                    PropertyID = 0x46
	PID_DESCRIPTION                   PropertyID = 0x1c
	PID_LOCATION                      PropertyID = 0x3a
)

type ReadProperty struct {
	Object   ObjectID   `json:"object"`
	Property PropertyID `json:"property"`
}

func (rp *ReadProperty) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x0c)
	if err := binary.Write(buf, binary.BigEndian, uint32(rp.Object)); err != nil {
		return nil, err
	}
	buf.WriteByte(0x19)
	buf.WriteByte(byte(rp.Property))
	return buf.Bytes(), nil
}

func (rp *ReadProperty) Unmarshal(b []byte) (leftovers []byte, err error) {
	buf := bytes.NewBuffer(b)
	leftovers = b
	if oidContextTag, _ := buf.ReadByte(); oidContextTag != 0x0c {
		return b, errInvalidPacket
	}
	var oid uint32
	if err = binary.Read(buf, binary.BigEndian, &oid); err != nil {
		return
	}
	rp.Object = ObjectID(oid)
	if pidContextTag, _ := buf.ReadByte(); pidContextTag != 0x19 {
		return b, errInvalidPacket
	}
	var pid byte
	if pid, err = buf.ReadByte(); err != nil {
		return
	}
	rp.Property = PropertyID(pid)
	bytesRead := len(b) - buf.Len()
	return b[bytesRead:], nil
}

func readInstanceNumber(b []byte) (leftovers []byte, instanceNumber uint32, err error) {
	buf := bytes.NewBuffer(b)
	leftovers = b
	var openByte, appByte, closeByte byte
	if openByte, err = buf.ReadByte(); openByte != 0x3e {
		return
	}
	if appByte, err = buf.ReadByte(); appByte != 0xc4 {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &instanceNumber); err != nil {
		return
	}
	if closeByte, err = buf.ReadByte(); closeByte != 0x3f {
		return
	}
	bytesRead := len(b) - buf.Len()
	leftovers = b[bytesRead:]
	instanceNumber &= 0x0003ffff
	return
}

func readVendorID(b []byte) (leftovers []byte, vendorID uint16, err error) {
	buf := bytes.NewBuffer(b)
	leftovers = b
	var openByte, appByte, closeByte byte
	if openByte, err = buf.ReadByte(); openByte != 0x3e {
		return
	}
	if appByte, err = buf.ReadByte(); appByte != 0x22 && appByte != 0x21 {
		return
	}
	if appByte == 0x22 {
		if err = binary.Read(buf, binary.BigEndian, &vendorID); err != nil {
			return
		}
	} else {
		var vendorIDByte byte
		if err = binary.Read(buf, binary.BigEndian, &vendorIDByte); err != nil {
			return
		}
		vendorID = uint16(vendorIDByte)
	}
	if closeByte, err = buf.ReadByte(); closeByte != 0x3f {
		return
	}
	bytesRead := len(b) - buf.Len()
	leftovers = b[bytesRead:]
	return
}

func readStringProperty(b []byte) (leftovers []byte, value string, err error) {
	buf := bytes.NewBuffer(b)
	leftovers = b
	var openByte, appByte, closeByte, lengthByte byte
	if openByte, err = buf.ReadByte(); openByte != 0x3e {
		return
	}
	if appByte, err = buf.ReadByte(); appByte&0xF8 != 0x70 {
		return
	}
	lengthBits := appByte & 0x07
	if lengthBits == 5 {
		if lengthByte, err = buf.ReadByte(); err != nil {
			return
		}
	} else {
		lengthByte = lengthBits
	}
	propertyBytes := make([]byte, lengthByte)
	var n int
	if n, err = buf.Read(propertyBytes); err != nil {
		return
	}
	if n != int(lengthByte) || lengthByte < 1 {
		err = errBACNetPacketTooShort
		return
	}
	value = string(propertyBytes[1:])
	if closeByte, err = buf.ReadByte(); closeByte != 0x3f {
		return
	}
	bytesRead := len(b) - buf.Len()
	leftovers = b[bytesRead:]
	return
}
