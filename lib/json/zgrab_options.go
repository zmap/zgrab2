package json

import "strings"

// ZGrabOptions holds the parsed value of a zgrab tag.
type ZGrabOptions struct {
	// Debug indicates that the field should be suppressed unless debugging
	// output is enabled.
	Debug bool

	// Raw is the raw value if the zgrab tag.
	Raw string
}

// ParseZGrabOptions parses the ZGrabOptions from the zgrab tag.
// Following parseTag, invalid values are simply ignored.
func ParseZGrabOptions(tag string) ZGrabOptions {
	ret := ZGrabOptions{
		Raw: tag,
	}
	if tag == "" {
		return ret
	}
	entries := strings.Split(tag, ",")

	for _, entry := range entries {
		switch strings.TrimSpace(entry) {
		case "debug":
			ret.Debug = true
		}
	}
	return ret
}