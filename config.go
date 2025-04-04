package zgrab2

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// Config is the high level framework options that will be parsed
// from the command line
type Config struct {
	OutputFileName     string          `short:"o" long:"output-file" default:"-" description:"Output filename, use - for stdout"`
	InputFileName      string          `short:"f" long:"input-file" default:"-" description:"Input filename, use - for stdin"`
	MetaFileName       string          `short:"m" long:"metadata-file" default:"-" description:"Metadata filename, use - for stderr"`
	LogFileName        string          `short:"l" long:"log-file" default:"-" description:"Log filename, use - for stderr"`
	Senders            int             `short:"s" long:"senders" default:"1000" description:"Number of send goroutines to use"`
	Debug              bool            `long:"debug" description:"Include debug fields in the output."`
	Flush              bool            `long:"flush" description:"Flush after each line of output."`
	GOMAXPROCS         int             `long:"gomaxprocs" default:"0" description:"Set GOMAXPROCS"`
	ConnectionsPerHost int             `long:"connections-per-host" default:"1" description:"Number of times to connect to each host (results in more output)"`
	ReadLimitPerHost   int             `long:"read-limit-per-host" default:"96" description:"Maximum total kilobytes to read for a single host (default 96kb)"`
	Prometheus         string          `long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled."`
	CustomDNS          string          `long:"dns" description:"Address of a custom DNS server for lookups. Default port is 53."`
	Multiple           MultipleCommand `command:"multiple" description:"Multiple module actions"`
	LocalAddrString    string          `long:"local-addr" description:"Local address(es) to bind to for outgoing connections. Comma-separated list of IP addresses, ranges (inclusive), or CIDR blocks, ex: 1.1.1.1-1.1.1.3, 2.2.2.2, 3.3.3.0/24"`
	LocalPortString    string          `long:"local-port" description:"Local port(s) to bind to for outgoing connections. Comma-separated list of ports or port ranges (inclusive) ex: 1200-1300,2000"`
	inputFile          *os.File
	outputFile         *os.File
	metaFile           *os.File
	logFile            *os.File
	inputTargets       InputTargetsFunc
	outputResults      OutputResultsFunc
	localAddrs         []net.IP // will be non-empty if user specified local addresses
	localPorts         []uint16 // will be non-empty if user specified local ports
}

// SetInputFunc sets the target input function to the provided function.
func SetInputFunc(f InputTargetsFunc) {
	config.inputTargets = f
}

// SetOutputFunc sets the result output function to the provided function.
func SetOutputFunc(f OutputResultsFunc) {
	config.outputResults = f
}

func init() {
	config.Multiple.ContinueOnError = true // set default for multiple value
	config.Multiple.BreakOnSuccess = false // set default for multiple value
}

var config Config

func validateFrameworkConfiguration() {
	// validate files
	if config.LogFileName == "-" {
		config.logFile = os.Stderr
	} else {
		var err error
		if config.logFile, err = os.Create(config.LogFileName); err != nil {
			log.Fatal(err)
		}
		log.SetOutput(config.logFile)
	}
	SetInputFunc(InputTargetsCSV)

	if config.InputFileName == "-" {
		config.inputFile = os.Stdin
	} else {
		var err error
		if config.inputFile, err = os.Open(config.InputFileName); err != nil {
			log.Fatal(err)
		}
	}

	if config.OutputFileName == "-" {
		config.outputFile = os.Stdout
	} else {
		var err error
		if config.outputFile, err = os.Create(config.OutputFileName); err != nil {
			log.Fatal(err)
		}
	}
	outputFunc := OutputResultsWriterFunc(config.outputFile)
	SetOutputFunc(outputFunc)

	if config.MetaFileName == "-" {
		config.metaFile = os.Stderr
	} else {
		var err error
		if config.metaFile, err = os.Create(config.MetaFileName); err != nil {
			log.Fatal(err)
		}
	}

	// Validate Go Runtime config
	if config.GOMAXPROCS < 0 {
		log.Fatalf("invalid GOMAXPROCS (must be positive, given %d)", config.GOMAXPROCS)
	}
	runtime.GOMAXPROCS(config.GOMAXPROCS)

	//validate/start prometheus
	if config.Prometheus != "" {
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			if err := http.ListenAndServe(config.Prometheus, nil); err != nil {
				log.Fatalf("could not run prometheus server: %s", err.Error())
			}
		}()
	}

	//validate senders
	if config.Senders <= 0 {
		log.Fatalf("need at least one sender, given %d", config.Senders)
	}

	// validate connections per host
	if config.ConnectionsPerHost <= 0 {
		log.Fatalf("need at least one connection, given %d", config.ConnectionsPerHost)
	}

	// Stop the lowliest idiot from using this to DoS people
	if config.ConnectionsPerHost > 50 {
		log.Fatalf("connectionsPerHost must be in the range [0,50]")
	}

	// Stop even third-party libraries from performing unbounded reads on untrusted hosts
	if config.ReadLimitPerHost > 0 {
		DefaultBytesReadLimit = config.ReadLimitPerHost * 1024
	}

	// Validate custom DNS
	if config.CustomDNS != "" {
		var err error
		if config.CustomDNS, err = addDefaultPortToDNSServerName(config.CustomDNS); err != nil {
			log.Fatalf("invalid DNS server address: %s", err)
		}
	}

	// If localAddrString is set, parse it into a list of IP addresses to use for source IPs
	if config.LocalAddrString != "" {
		ips, err := extractIPAddresses(config.LocalAddrString)
		if err != nil {
			log.Fatalf("could not extract IP addresses from address string %s: %s", config.LocalAddrString, err)
		}
		config.localAddrs = ips
	}

	// If localPortString is set, parse it into a list of ports to use for source ports
	if config.LocalPortString != "" {
		ports, err := extractPorts(config.LocalPortString)
		if err != nil {
			log.Fatalf("could not extract ports from port string %s: %s", config.LocalPortString, err)
		}
		config.localPorts = ports
	}
}

// extractIPAddresses takes in a string of comma-separated IP addresses, ranges, or CIDR blocks and returns a de-duped
// list of IP addresses, or an error if the string is invalid. Whitespace is trimmed from each address string and the
// ranges are inclusive.
// See config_test.go for examples of valid and invalid strings
func extractIPAddresses(ipString string) ([]net.IP, error) {
	ipsMap := make(map[string]net.IP)
	for _, addr := range strings.Split(ipString, ",") {
		// this addr is either an IP address, ip address range, or a CIDR range
		addr = strings.TrimSpace(addr) // remove whitespace
		_, ipnet, err := net.ParseCIDR(addr)
		if err == nil {
			// CIDR range, append all constituents
			for currentIP := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(currentIP); incrementIP(currentIP) {
				tempIP := duplicateIP(currentIP)
				ipsMap[currentIP.String()] = tempIP
			}
			continue
		}
		if strings.Contains(addr, "-") {
			// IP range
			parts := strings.Split(addr, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid IP range %s", addr)
			}
			parts[0] = strings.TrimSpace(parts[0])
			parts[1] = strings.TrimSpace(parts[1])
			startIP := net.ParseIP(parts[0])
			endIP := net.ParseIP(parts[1])
			if startIP == nil {
				return nil, fmt.Errorf("invalid start IP %s of IP range", parts[0])
			}
			if endIP == nil {
				return nil, fmt.Errorf("invalid end IP %s of IP range", parts[1])
			}
			if compareIPs(startIP, endIP) > 0 {
				return nil, fmt.Errorf("start IP %s is greater than end IP %s of IP range", startIP.String(), endIP.String())
			}
			for currentIP := startIP; compareIPs(currentIP, endIP) <= 0; incrementIP(currentIP) {
				tempIP := duplicateIP(currentIP)
				ipsMap[currentIP.String()] = tempIP
			}
			continue
		}
		// single IP
		castIP := net.ParseIP(addr)
		if castIP != nil {
			ipsMap[castIP.String()] = castIP
		} else {
			return nil, fmt.Errorf("could not parse IP address %s", addr)
		}
	}
	// build list from de-duped map
	ips := make([]net.IP, 0, len(ipsMap))
	for _, i := range ipsMap {
		ip := i
		ips = append(ips, ip)
	}
	return ips, nil
}

// extractPorts takes in a string of comma-separated ports or port ranges (80-443) and returns a de-duped list of ports
// Whitespace is trimmed from each port string, and the port range is inclusive.
func extractPorts(portString string) ([]uint16, error) {
	portMap := make(map[uint16]struct{})
	for _, portStr := range strings.Split(portString, ",") {
		portStr = strings.TrimSpace(portStr)
		if strings.Contains(portStr, "-") {
			// port range
			parts := strings.Split(portStr, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range %s, valid range ex: '80-443'", portStr)
			}
			startPort, err := parsePortString(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid start port %s of port range: %v", parts[0], err)
			}
			endPort, err := parsePortString(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid end port %s of port range: %v", parts[1], err)
			}
			if startPort >= endPort {
				return nil, fmt.Errorf("start port %d must be less than end port %d", startPort, endPort)
			}
			// validation complete, add all ports in range
			for i := startPort; i <= endPort; i++ {
				portMap[i] = struct{}{}
			}
		} else {
			// single port
			port, err := parsePortString(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid port %s: %v", portStr, err)
			}
			portMap[port] = struct{}{}
		}
	}
	// build list from de-duped map
	ports := make([]uint16, 0, len(portMap))
	for port := range portMap {
		ports = append(ports, port)
	}
	return ports, nil
}

// parsePortString converts a string to a uint16 port number after removing whitespace
// Checks for validity of the port number and returns an error if invalid
func parsePortString(portStr string) (uint16, error) {
	minimumPort := uint64(1)     // inclusive
	maximumPort := uint64(65535) // inclusive
	port, err := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %s: %v", portStr, err)
	}
	if port < minimumPort {
		return 0, fmt.Errorf("port %s must be in the range [%d,%d]", portStr, minimumPort, maximumPort)
	}
	if port > maximumPort {
		return 0, fmt.Errorf("port %s must be in the range [%d,%d]", portStr, minimumPort, maximumPort)
	}
	return uint16(port), nil
}

// GetMetaFile returns the file to which metadata should be output
func GetMetaFile() *os.File {
	return config.metaFile
}

func includeDebugOutput() bool {
	return config.Debug
}
