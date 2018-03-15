package zgrab2

import "errors"

// ErrMismatchedFlags is thrown if the flags for one module type are
// passed to an incompatible module type.
var ErrMismatchedFlags = errors.New("mismatched flag/module")

// ErrInvalidArguments is thrown if the command-line arguments invalid.
var ErrInvalidArguments = errors.New("invalid arguments")

// ErrInvalidResponse is returned when the server returns a syntactically-invalid response.
var ErrInvalidResponse = errors.New("invalid response")

// ErrUnexpectedResponse is returned when the server returns a syntactically-valid but unexpected response.
var ErrUnexpectedResponse = errors.New("unexpected response")
