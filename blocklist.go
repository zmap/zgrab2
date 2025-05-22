package zgrab2

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/censys/cidranger"
)

func stripComments(line, commentDelimiter string) string {
	// Remove comments from the line
	if idx := strings.Index(line, commentDelimiter); idx != -1 {
		return line[:idx]
	}
	return line
}

// readBlocklist reads a blocklist file that contains CIDR ranges, IPs, or IP ranges
// It returns a path-compressed trie of CIDR ranges that can be used to check if an IP address is in the blocklist
func readBlocklist(fileName string) (cidranger.Ranger, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read blocklist file: %w", err)
	}
	strData := string(data)
	// Remove comments and empty lines
	cidrStrings := make([]string, 0)
	for _, line := range strings.Split(strData, "\n") {
		line = stripComments(line, "#")
		line = strings.TrimSpace(line) // Trim whitespace
		if len(line) > 0 {
			cidrStrings = append(cidrStrings, line)
		}
	}
	var cidrs []net.IPNet
	cidrs, err = extractCIDRRanges(cidrStrings)
	if err != nil {
		return nil, fmt.Errorf("failed to convert blacklist into CIDRs: %w", err)
	}
	ranger := cidranger.NewPCTrieRanger()
	for _, cidr := range cidrs {
		if err = ranger.Insert(cidranger.NewBasicRangerEntry(cidr)); err != nil {
			return nil, fmt.Errorf("failed to insert CIDR (%s) into ranger: %w", cidr.String(), err)
		}
	}
	return ranger, nil
}
