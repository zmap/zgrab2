package bacnet

import (
	"errors"
	"net"
)

const (
	MAX_BACNET_FRAME_LEN = 1476
)

// VLC Header constants
const (
	VLC_TYPE_IP               byte = 0x81
	VLC_FUNCTION_UNICAST_NPDU byte = 0x0a
)

// NPDU header constant
const (
	NPDU_VERSION_ASHRAE_135_1995 byte = 0x01
	NPDU_FLAG_EXPECTING_RESPONSE byte = 0x04
)

// APDU Server Choice constants
const (
	SERVER_CHOICE_READ_PROPERTY byte = 0x0c
)

var (
	errBACNetPacketTooShort error = errors.New("BACNet packet too short")
	errInvalidPacket        error = errors.New("Invalid BACNet packet")
	errNotBACNet            error = errors.New("Not a BACNet packet")
)

func SendVLC(c net.Conn, payload []byte) error {
	if len(payload) > 1472 {
		return errors.New("payload too long")
	}
	vlc := VLC{
		Type:     VLC_TYPE_IP,
		Function: VLC_FUNCTION_UNICAST_NPDU,
		Length:   4 + uint16(len(payload)),
	}
	b, _ := vlc.Marshal()
	b = append(b, payload...)
	if _, err := c.Write(b); err != nil {
		return err
	}
	return nil
}

func ReadVLC(c net.Conn) (vlc *VLC, npdu *NPDU, apdu *APDU, leftovers []byte, err error, isBACNet bool) {
	b := make([]byte, MAX_BACNET_FRAME_LEN)
	n, err := c.Read(b)
	if err != nil {
		return
	}
	b = b[0:n]
	leftovers = b
	vlc = new(VLC)
	if leftovers, err = vlc.Unmarshal(leftovers); err != nil {
		return
	}
	isBACNet = true
	npdu = new(NPDU)
	if leftovers, err = npdu.Unmarshal(leftovers); err != nil {
		return
	}
	apdu = new(APDU)
	if leftovers, err = apdu.Unmarshal(leftovers); err != nil {
		return
	}
	return
}
