package bacnet

import "net"

type Log struct {
	IsBACNet                    bool   `json:"is_bacnet"`
	InstanceNumber              uint32 `json:"instance_number"`
	VendorID                    uint16 `json:"vendor_id"`
	VendorName                  string `json:"vendor_name,omitempty"`
	FirmwareRevision            string `json:"firmware_revision,omitempty"`
	ApplicationSoftwareRevision string `json:"application_software_revision,omitempty"`
	ObjectName                  string `json:"object_name,omitempty"`
	ModelName                   string `json:"model_name,omitempty"`
	Description                 string `json:"description,omitempty"`
	Location                    string `json:"location,omitempty"`
}

func (log *Log) sendReadProperty(c net.Conn, oid ObjectID, pid PropertyID) ([]byte, error, bool) {
	rp := NewReadPropertyRequest(oid, pid)
	b, err := rp.Marshal()
	if err != nil {
		return nil, err, false
	}
	if err := SendVLC(c, b); err != nil {
		return nil, err, false
	}
	var body []byte
	var isBACNet bool
	_, _, _, body, err, isBACNet = ReadVLC(c)
	if err != nil {
		return nil, err, isBACNet
	}
	r := new(ReadProperty)
	if body, err = r.Unmarshal(body); err != nil {
		return nil, err, isBACNet
	}
	return body, nil, true
}

func (log *Log) queryStringProperty(c net.Conn, oid ObjectID, pid PropertyID) (value string, err error) {
	var body []byte
	if body, err, _ = log.sendReadProperty(c, oid, pid); err != nil {
		return
	}
	_, value, err = readStringProperty(body)
	return
}

func (log *Log) QueryDeviceID(c net.Conn) (err error) {
	var body []byte
	if body, err, log.IsBACNet = log.sendReadProperty(c, OID_ANY, PID_OID); err != nil {
		return
	}
	if !log.IsBACNet {
		return errNotBACNet
	}
	var instanceNumber uint32
	_, instanceNumber, err = readInstanceNumber(body)
	if err != nil {
		return err
	}
	log.InstanceNumber = instanceNumber
	return nil
}

func (log *Log) QueryVendorNumber(c net.Conn) (err error) {
	var body []byte
	if body, err, _ = log.sendReadProperty(c, OID_ANY, PID_VENDOR_NUMBER); err != nil {
		return
	}
	var vendorID uint16
	_, vendorID, err = readVendorID(body)
	if err != nil {
		return err
	}
	log.VendorID = vendorID
	return nil
}

func (log *Log) QueryVendorName(c net.Conn) (err error) {
	log.VendorName, err = log.queryStringProperty(c, OID_ANY, PID_VENDOR_NAME)
	return
}

func (log *Log) QueryFirmwareRevision(c net.Conn) (err error) {
	log.FirmwareRevision, err = log.queryStringProperty(c, OID_ANY, PID_FIRMWARE_REVISION)
	if err == nil && len(log.FirmwareRevision) == 0 {
		log.FirmwareRevision = "0.0"
	}
	return
}

func (log *Log) QueryApplicationSoftwareRevision(c net.Conn) (err error) {
	log.ApplicationSoftwareRevision, err = log.queryStringProperty(c, OID_ANY, PID_APPLICATION_SOFTWARE_REVISION)
	if err == nil && len(log.ApplicationSoftwareRevision) == 0 {
		log.ApplicationSoftwareRevision = "0.0"
	}
	return
}

func (log *Log) QueryObjectName(c net.Conn) (err error) {
	log.ObjectName, err = log.queryStringProperty(c, OID_ANY, PID_OBJECT_NAME)
	return
}

func (log *Log) QueryModelName(c net.Conn) (err error) {
	log.ModelName, err = log.queryStringProperty(c, OID_ANY, PID_MODEL_NAME)
	return
}

func (log *Log) QueryDescription(c net.Conn) (err error) {
	log.Description, err = log.queryStringProperty(c, OID_ANY, PID_DESCRIPTION)
	return
}

func (log *Log) QueryLocation(c net.Conn) (err error) {
	log.Location, err = log.queryStringProperty(c, OID_ANY, PID_LOCATION)
	return
}
