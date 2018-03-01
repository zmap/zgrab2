package zgrab2

import (
	"fmt"
)

func ExampleMapFlagsToSet_success() {
	output, unknowns := MapFlagsToSet(0xb, func(bit uint64) (string, error) {
		return fmt.Sprintf("bit0x%01x", bit), nil
	})
	for k, v := range output {
		fmt.Printf("%s: %v\n", k, v)
	}
	for _, v := range unknowns {
		fmt.Printf("Unknown: 0x%01x", v)
	}
	// Unordered Output:
	// bit0x1: true
	// bit0x2: true
	// bit0x8: true
}

func ExampleMapFlagsToSet_error() {
	output, unknowns := MapFlagsToSet(0x1b, func(bit uint64) (string, error) {
		if bit < 0x10 {
			return fmt.Sprintf("bit0x%01x", bit), nil
		} else {
			return "", fmt.Errorf("Unrecognized flag 0x%02x", bit)
		}
	})
	for k, v := range output {
		fmt.Printf("%s: %v\n", k, v)
	}
	for _, v := range unknowns {
		fmt.Printf("Unknown: 0x%02x", v)
	}
	// Unordered Output:
	// bit0x1: true
	// bit0x2: true
	// bit0x8: true
	// Unknown: 0x10
}

func ExampleFlagsToSet() {
	output, unknowns := FlagsToSet(0x5, WidenMapKeys(map[int]string{
		0x1: "bit0",
		0x2: "bit1",
		0x8: "bit3",
	}))
	for k, v := range output {
		fmt.Printf("%s: %v\n", k, v)
	}
	for _, v := range unknowns {
		fmt.Printf("Unknown: 0x%01x", v)
	}
	// Unordered Output:
	// bit0: true
	// Unknown: 0x4
}

func ExampleListFlagsToSet() {
	output, unknowns := ListFlagsToSet(0x5, []string{
		"bit0",
		"bit1",
		"",
		"bit3",
	})
	for k, v := range output {
		fmt.Printf("%s: %v\n", k, v)
	}
	for _, v := range unknowns {
		fmt.Printf("Unknown: 0x%01x", v)
	}
	// Unordered Output:
	// bit0: true
	// Unknown: 0x4
}
