package siemens

import "errors"

var (
	errS7PacketTooShort = errors.New("s7 packet too short")
	errInvalidPacket    = errors.New("invalid S7 packet")
	errNotS7            = errors.New("not a S7 packet")
)

// S7Error provides an interface to get S7 errors.
type S7Error struct{}

var (
	// S7_ERROR_CODES maps error codes to the friendly error string
	S7_ERROR_CODES = map[uint32]string{
		// s7 data errors
		0x05: "address error",
		0x0a: "item not available",
		// s7 header errors
		0x8104: "context not supported",
		0x8500: "wrong PDU size",
	}
)

// New gets an S7 error instance for the given error code.
// TODO: Shouldn't it be sharing a single error instance, rather than returning a new error instance each time?
func (s7Error *S7Error) New(errorCode uint32) error {
	return errors.New(S7_ERROR_CODES[errorCode])
}
