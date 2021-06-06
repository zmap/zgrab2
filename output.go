package zgrab2

import (
	"bufio"
	"fmt"
	"io"
)

// FlagMap is a function that maps a single-bit bitmask (i.e. a number of the
// form (1 << x)) to a string representing that bit.
// If the input is not valid / recognized, it should return a non-nil error,
// which will cause the flag to be added to the "unknowns" list.
type FlagMap func(uint64) (string, error)

// MapFlagsToSet gets the "set" (map of strings to true) of values corresponding
// to the bits in flags. For each bit i set in flags, the result will have
// result[mapping(i << i)] = true.
// Any bits for which the mapping returns a non-nil error are instead appended
// to the unknowns list.
func MapFlagsToSet(flags uint64, mapping FlagMap) (map[string]bool, []uint64) {
	ret := make(map[string]bool)
	unknowns := []uint64{}
	for i := uint8(0); i < 64; i++ {
		if flags == 0 {
			break
		}
		bit := (flags & 1) << i
		if bit > 0 {
			str, err := mapping(bit)
			if err != nil {
				unknowns = append(unknowns, bit)
			} else {
				ret[str] = true
			}
		}
		flags >>= 1
	}
	return ret, unknowns
}

// GetFlagMapFromMap returns a FlagMap function that uses mapping to do the
// mapping. Values not present in the map are treated as unknown, and a non-nil
// error is returned in those cases.
func GetFlagMapFromMap(mapping map[uint64]string) FlagMap {
	return func(bit uint64) (string, error) {
		ret, ok := mapping[bit]
		if ok {
			return ret, nil
		}
		return "", fmt.Errorf("Unknown flag 0x%x", bit)
	}
}

// GetFlagMapFromList returns a FlagMap function mapping the ith bit to the
// ith entry of bits.
// bits is a list of labels for the corresponding bits; any empty strings (and
// bits beyond the end of the list) are treated as unknown.
func GetFlagMapFromList(bits []string) FlagMap {
	mapping := make(map[uint64]string)
	for i, v := range bits {
		if v != "" {
			mapping[uint64(1)<<uint8(i)] = v
		}
	}
	return GetFlagMapFromMap(mapping)
}

// FlagsToSet converts an integer flags variable to a set of string labels
// corresponding to each bit, in the format described by the wiki (see
// https://github.com/zmap/zgrab2/wiki/Scanner-details).
// The mapping maps the bit mask value (i.e. a number of the form (1 << x)) to
// the label for that bit.
// Flags not present in mapping are appended to the unknown list.
func FlagsToSet(flags uint64, mapping map[uint64]string) (map[string]bool, []uint64) {
	mapper := GetFlagMapFromMap(mapping)
	return MapFlagsToSet(flags, mapper)
}

// ListFlagsToSet converts an integer flags variable to a set of string labels
// corresponding to each bit, in the format described by the wiki (see
// https://github.com/zmap/zgrab2/wiki/Scanner-details).
// The ith entry of labels gives the label for the ith bit (i.e. flags & (1<<i)).
// Empty strings in labels are treated as unknown, as are bits beyond the end
// of the list. Unknown flags are appended to the unknown list.
func ListFlagsToSet(flags uint64, labels []string) (map[string]bool, []uint64) {
	mapper := GetFlagMapFromList(labels)
	return MapFlagsToSet(flags, mapper)
}

// WidenMapKeys8 copies a map with uint8 keys into an equivalent map with uint64
// keys for use in the FlagsToSet function.
func WidenMapKeys8(input map[uint8]string) map[uint64]string {
	ret := make(map[uint64]string, len(input))
	for k, v := range input {
		ret[uint64(k)] = v
	}
	return ret
}

// WidenMapKeys16 copies a map with uint8 keys into an equivalent map with
// uint64 keys for use in the FlagsToSet function.
func WidenMapKeys16(input map[uint16]string) map[uint64]string {
	ret := make(map[uint64]string, len(input))
	for k, v := range input {
		ret[uint64(k)] = v
	}
	return ret
}

// WidenMapKeys32 copies a map with uint8 keys into an equivalent map with
// uint64 keys for use in the FlagsToSet function.
func WidenMapKeys32(input map[uint32]string) map[uint64]string {
	ret := make(map[uint64]string, len(input))
	for k, v := range input {
		ret[uint64(k)] = v
	}
	return ret
}

// WidenMapKeys copies a map with int keys into an equivalent map with uint64
// keys for use in the FlagsToSet function.
func WidenMapKeys(input map[int]string) map[uint64]string {
	ret := make(map[uint64]string, len(input))
	for k, v := range input {
		ret[uint64(k)] = v
	}
	return ret
}

// OutputResultsFunc is a function type for result output functions.
//
// A function of this type receives results on the provided channel
// and outputs them somehow.  It returns nil if there are no further
// results or error.
type OutputResultsFunc func(results <-chan []byte) error

// OutputResultsWriterFunc returns an OutputResultsFunc that wraps an io.Writer
// in a buffered writer, and uses OutputResults.
func OutputResultsWriterFunc(w io.Writer) OutputResultsFunc {
	buf := bufio.NewWriter(w)
	return func(result <-chan []byte) error {
		defer buf.Flush()
		return OutputResults(buf, result)
	}
}

// OutputResults writes results to a buffered Writer from a channel.
func OutputResults(w *bufio.Writer, results <-chan []byte) error {
	for result := range results {
		if _, err := w.Write(result); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
		if config.Flush {
			w.Flush()
		}
	}
	return nil
}
