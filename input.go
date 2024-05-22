package zgrab2

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// ParseCSVTarget takes a record from a CSV-format input file and
// returns the specified ipnet, domain, tag and port or an error.
//
// ZGrab2 input files have four fields:
//
//	IP, DOMAIN, TAG, PORT
//
// Each line specifies a target to scan by its IP address, domain
// name or both, as well as an optional tag used to determine which
// scanners will be invoked.
//
// Port number has been added to the end of the line for compatibility reasons.
// A CIDR block may be provided in the IP field, in which case the
// framework expands the record into targets for every address in the
// block.
//
// Trailing empty fields may be omitted.
// Comment lines begin with #, and empty lines are ignored.
func ParseCSVTarget(fields []string) (ipnet *net.IPNet, domain string, tag string, port string, err error) {
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	if len(fields) > 0 && fields[0] != "" {
		if ip := net.ParseIP(fields[0]); ip != nil {
			ipnet = &net.IPNet{IP: ip}
		} else if _, cidr, er := net.ParseCIDR(fields[0]); er == nil {
			ipnet = cidr
		} else if len(fields) != 1 {
			err = fmt.Errorf("can't parse %q as an IP address or CIDR block", fields[0])
			return
		}
	}
	if len(fields) > 1 {
		domain = fields[1]
	}
	if len(fields) > 2 {
		tag = fields[2]
	}
	// Use string for port to allow empty port
	if len(fields) > 3 {
		port = fields[3]
	}
	if len(fields) > 4 {
		err = fmt.Errorf("too many fields: %q", fields)
		return
	}

	// For legacy reasons, we also allow targets of the form:
	// DOMAIN
	if ipnet == nil && len(fields) == 1 {
		domain = fields[0]
	}

	if ipnet == nil && domain == "" {
		err = fmt.Errorf("record doesn't specify an address, network, or domain: %v", fields)
		return
	}
	return
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func duplicateIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// InputTargetsCSV is an InputTargetsFunc that calls GetTargetsCSV with
// the CSV file provided on the command line.
func InputTargetsCSV(ch chan<- ScanTarget) error {
	return GetTargetsCSV(config.inputFile, ch)
}

// GetTargetsCSV reads targets from a CSV source, generates ScanTargets,
// and delivers them to the provided channel.
func GetTargetsCSV(source io.Reader, ch chan<- ScanTarget) error {
	csvreader := csv.NewReader(source)
	csvreader.Comment = '#'
	csvreader.FieldsPerRecord = -1 // variable
	for {
		fields, err := csvreader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if len(fields) == 0 {
			continue
		}
		ipnet, domain, tag, port, err := ParseCSVTarget(fields)
		if err != nil {
			log.Errorf("parse error, skipping: %v", err)
			continue
		}
		var ip net.IP
		var port_uint uint
		if port != "" {
			port_int, err := strconv.Atoi(port)
			port_uint = uint(port_int)
			if err != nil {
				log.Errorf("parse error, skipping: %v", err)
				continue
			}
		}
		if ipnet != nil {
			if ipnet.Mask != nil {
				// expand CIDR block into one target for each IP
				for ip = ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
					if port == "" {
						ch <- ScanTarget{IP: duplicateIP(ip), Domain: domain, Tag: tag}
					} else {
						ch <- ScanTarget{IP: duplicateIP(ip), Domain: domain, Tag: tag, Port: &port_uint}
					}
				}
				continue
			} else {
				ip = ipnet.IP
			}
		}
		if port == "" {
			ch <- ScanTarget{IP: ip, Domain: domain, Tag: tag}
		} else {
			ch <- ScanTarget{IP: ip, Domain: domain, Tag: tag, Port: &port_uint}
		}
	}
	return nil
}

// InputTargetsFunc is a function type for target input functions.
//
// A function of this type generates ScanTargets on the provided
// channel.  It returns nil if there are no further inputs or error.
type InputTargetsFunc func(ch chan<- ScanTarget) error
