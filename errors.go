package zgrab2

import "errors"

// ErrMismatchedFlags is thrown if the flags for one module type are 
// passed to an incompatible module type.
var ErrMismatchedFlags = errors.New("mismatched flag/module")

// ErrInvalidArguments is thrown if the command-line arguments invalid.
var ErrInvalidArguments = errors.New("invalid arguments")
