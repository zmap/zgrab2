package zgrab2

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/censys/cidranger"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	IPVersionCapabilityTimeout     = 10 * time.Second
	IPVersionCapabilityIPv4Address = "1.1.1.1:80"              // Cloudflare has this IP/Port redirect to https://one.one.one.one. We can use it to test if this host has IPv4 connectivity
	IPVersionCapabilityIPv6Address = "2606:4700:4700::1111:80" // Same as above for IPv6
)

// Config is the high level framework options that will be parsed
// from the command line
type Config struct {
	OutputFileName        string          `short:"o" long:"output-file" default:"-" description:"Output filename, use - for stdout"`
	InputFileName         string          `short:"f" long:"input-file" default:"-" description:"Input filename, use - for stdin"`
	MetaFileName          string          `short:"m" long:"metadata-file" default:"-" description:"Metadata filename, use - for stderr."`
	BlocklistFileName     string          `short:"b" long:"blocklist-file" default:"-" description:"Blocklist filename, use - for $(HOME)/.config/zgrab2/blocklist.conf"`
	StatusUpdatesFileName string          `short:"u" long:"status-updates-file" default:"-" description:"Status updates filename, use - for stderr."`
	LogFileName           string          `short:"l" long:"log-file" default:"-" description:"Log filename, use - for stderr"`
	Senders               int             `short:"s" long:"senders" default:"1000" description:"Number of send goroutines to use"`
	Debug                 bool            `long:"debug" description:"Include debug fields in the output."`
	Flush                 bool            `long:"flush" description:"Flush after each line of output."`
	GOMAXPROCS            int             `long:"gomaxprocs" default:"0" description:"Set GOMAXPROCS"`
	ConnectionsPerHost    int             `long:"connections-per-host" default:"1" description:"Number of times to connect to each host (results in more output)"`
	ReadLimitPerHost      int             `long:"read-limit-per-host" default:"96" description:"Maximum total kilobytes to read for a single host (default 96kb)"`
	Prometheus            string          `long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled."`
	CustomDNS             string          `long:"dns-resolvers" description:"Address of a custom DNS server(s) for lookups, comma-delimited. Default port is 53. Ex: 1.1.1.1:53,8.8.8.8. Uses the OS-default resolvers if not set."`
	Multiple              MultipleCommand `command:"multiple" description:"Multiple module actions"`
	LocalAddrString       string          `long:"local-addr" description:"Local address(es) to bind to for outgoing connections. Comma-separated list of IP addresses, ranges (inclusive), or CIDR blocks, ex: 1.1.1.1-1.1.1.3, 2.2.2.2, 3.3.3.0/24"`
	LocalPortString       string          `long:"local-port" description:"Local port(s) to bind to for outgoing connections. Comma-separated list of ports or port ranges (inclusive) ex: 1200-1300,2000"`
	inputFile             *os.File
	outputFile            *os.File
	metaFile              *os.File
	statusUpdatesFile     *os.File
	logFile               *os.File
	inputTargets          InputTargetsFunc
	outputResults         OutputResultsFunc
	customDNSNameservers  []string // will be non-empty if user specified custom DNS, we'll check these are reachable before populating
	localAddrs            []net.IP // will be non-empty if user specified local addresses
	localPorts            []uint16 // will be non-empty if user specified local ports
	useIPv4               bool     // true if zgrab should use IPv4 addresses after resolving domains
	useIPv6               bool
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
var blocklist cidranger.Ranger

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
	} else if len(config.MetaFileName) > 0 {
		var err error
		if config.metaFile, err = os.Create(config.MetaFileName); err != nil {
			log.Fatal(fmt.Errorf("error creating meta file: %w", err))
		}
	}

	if config.StatusUpdatesFileName == "-" {
		config.statusUpdatesFile = os.Stderr
	} else if len(config.StatusUpdatesFileName) > 0 {
		var err error
		if config.statusUpdatesFile, err = os.Create(config.StatusUpdatesFileName); err != nil {
			log.Fatal(fmt.Errorf("error creating status updates file: %w", err))
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

	// If localAddrString is set, parse it into a list of IP addresses to use for source IPs
	if config.LocalAddrString != "" {
		ips, err := extractIPAddresses(strings.Split(config.LocalAddrString, ","))
		if err != nil {
			log.Fatalf("could not extract IP addresses from address string %s: %s", config.LocalAddrString, err)
		}
		config.localAddrs = ips
		for _, ip := range ips {
			if ip == nil {
				log.Fatalf("could not extract IP addresses from address string: %s", ip)
			}
			if ip.To4() != nil {
				config.useIPv4 = true
			} else if ip.To16() != nil {
				config.useIPv6 = true
			} else {
				log.Fatalf("invalid local address: %s", ip)
			}
		}
	}

	if !config.useIPv4 && !config.useIPv6 {
		// We need to decide whether we'll request A and/or AAAA records when resolving domains to IPs.
		// The user hasn't specified any local addresses, so we'll detect the system's capabilities.
		// Simply detecting if the host has a loopback IPv6 is not enough, some systems have IPv6 interfaces, but ISP
		// won't support.
		// Note on Local Addresses: If the user specifies local addresses to use, we can detect IP capability from those
		// and we won't enter this. Just wanted to callout we're not leaking the user's local addresses to the internet
		// by not using them here.
		supportsIPv4 := make(chan bool)
		supportsIPv6 := make(chan bool)
		detectIPSupportFunc := func(network, address string, c chan bool) {
			conn, err := net.DialTimeout(network, address, IPVersionCapabilityTimeout)
			if err == nil {
				c <- true // notify that we can reach the address
				conn.Close()
			}
			close(c)
		}
		go detectIPSupportFunc("tcp4", IPVersionCapabilityIPv4Address, supportsIPv4)
		go detectIPSupportFunc("tcp6", IPVersionCapabilityIPv6Address, supportsIPv6)

		// Wait for the results
		heardFromIPv4, heardFromIPv6 := false, false
		for !heardFromIPv4 || !heardFromIPv6 { // we expect a result from both channels
			select {
			case ipv4, ok := <-supportsIPv4:
				if ok && ipv4 {
					config.useIPv4 = true
				}
				heardFromIPv4 = true
			case ipv6, ok := <-supportsIPv6:
				if ok && ipv6 {
					config.useIPv6 = true
				}
				heardFromIPv6 = true
			}
		}
		if !config.useIPv4 && !config.useIPv6 {
			log.Fatalf("could not reach one.one.one.one by either IPv4/IPv6 to detect IP capability, are you connected to the internet?")
		}
	}

	// Validate custom DNS must occur after setting useIPv4 and useIPv6
	if config.CustomDNS != "" {
		var err error
		if config.customDNSNameservers, err = parseCustomDNSString(config.CustomDNS); err != nil {
			log.Fatalf("invalid DNS server address: %s", err)
		}
	}

	// If localPortString is set, parse it into a list of ports to use for source ports
	if config.LocalPortString != "" {
		ports, err := extractPorts(config.LocalPortString)
		if err != nil {
			log.Fatalf("could not extract ports from port string %s: %s", config.LocalPortString, err)
		}
		config.localPorts = ports
	}
	if len(config.BlocklistFileName) > 0 {
		if config.BlocklistFileName == "-" {
			// use the default location
			config.BlocklistFileName = os.Getenv("HOME") + "/.config/zgrab2/blocklist.conf"
		}
		var err error
		blocklist, err = readBlocklist(config.BlocklistFileName)
		if err != nil {
			log.Fatalf("could not read blocklist file %s: %s", config.BlocklistFileName, err)
		}
	} else {
		// initialize to empty blocklist
		blocklist = cidranger.NewPCTrieRanger()
	}
}

// GetMetaFile returns the file to which metadata should be output
func GetMetaFile() *os.File {
	return config.metaFile
}

func includeDebugOutput() bool {
	return config.Debug
}
