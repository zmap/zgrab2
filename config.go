package zgrab2

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/censys/cidranger"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	IPVersionCapabilityTimeout     = 10 * time.Second
	IPVersionCapabilityIPv4Address = "1.1.1.1:80"              // Cloudflare has this IP/Port redirect to https://one.one.one.one. We can use it to test if this host has IPv4 connectivity
	IPVersionCapabilityIPv6Address = "2606:4700:4700::1111:80" // Same as above for IPv6
)

type GeneralOptions struct {
	Senders          int    `short:"s" long:"senders" default:"1000" description:"Number of send goroutines to use"`
	GOMAXPROCS       int    `long:"gomaxprocs" default:"0" description:"Set GOMAXPROCS"`
	Prometheus       string `long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled."`
	ReadLimitPerHost int    `long:"read-limit-per-host" default:"96" description:"Maximum total kilobytes to read for a single host (default 96kb)"`
}

type InputOutputOptions struct {
	BlocklistFileName     string `short:"b" long:"blocklist-file" default:"-" description:"Blocklist filename, use - for $(HOME)/.config/zgrab2/blocklist.conf"`
	InputFileName         string `short:"f" long:"input-file" default:"-" description:"Input filename, use - for stdin"`
	LogFileName           string `short:"l" long:"log-file" default:"-" description:"Log filename, use - for stderr"`
	MetaFileName          string `short:"m" long:"metadata-file" default:"-" description:"Metadata filename, use - for stderr."`
	OutputFileName        string `short:"o" long:"output-file" default:"-" description:"Output filename, use - for stdout"`
	StatusUpdatesFileName string `short:"u" long:"status-updates-file" default:"-" description:"Status updates filename, use - for stderr."`
	Debug                 bool   `long:"debug" description:"Include debug fields in the output."`
	Flush                 bool   `long:"flush" description:"Flush after each line of output."`
}

type NetworkingOptions struct {
	ConnectionsPerHost   int           `long:"connections-per-host" default:"1" description:"Number of times to connect to each host (results in more output)"`
	DNSServerRateLimit   int           `long:"dns-rate-limit" default:"10000" description:"Rate limit for DNS lookups per second."`
	DNSResolutionTimeout time.Duration `long:"dns-resolution-timeout" default:"10s" description:"Timeout for DNS resolution of target hostnames. Default is 10 seconds."`
	CustomDNS            string        `long:"dns-resolvers" description:"Address of a custom DNS server(s) for lookups, comma-delimited. Default port is 53. Ex: 1.1.1.1:53,8.8.8.8. Uses the OS-default resolvers if not set."`
	LocalAddrString      string        `long:"local-addr" description:"Local address(es) to bind to for outgoing connections. Comma-separated list of IP addresses, ranges (inclusive), or CIDR blocks, ex: 1.1.1.1-1.1.1.3, 2.2.2.2, 3.3.3.0/24"`
	LocalPortString      string        `long:"local-port" description:"Local port(s) to bind to for outgoing connections. Comma-separated list of ports or port ranges (inclusive) ex: 1200-1300,2000"`
	UserIPv4Choice       *bool         `long:"resolve-ipv4" description:"Use IPv4 for resolving domains (accept A records). True by default, use only --resolve-ipv6 for IPv6 only resolution. If used with --resolve-ipv6, will use both IPv4 and IPv6."`
	UserIPv6Choice       *bool         `long:"resolve-ipv6" description:"Use IPv6 for resolving domains (accept AAAA records). IPv6 is disabled by default. If --resolve-ipv4 is not set and --resolve-ipv6 is, will only use IPv6. If used with --resolve-ipv4, will use both IPv4 and IPv6."`
	ServerRateLimit      int           `long:"server-rate-limit" default:"20" description:"Per-IP rate limit for connections to targets per second."`
}

// Config is the high level framework options that will be parsed
// from the command line
type Config struct {
	GeneralOptions                       // CLI Options related to general framework configuration. Don't fit into any other category
	InputOutputOptions                   // CLI Options related to I/O. Just affects organization of --help
	NetworkingOptions                    // CLI Options related to networking. Just affects organization of --help
	Multiple             MultipleCommand `command:"multiple" description:"Multiple module actions"`
	inputFile            *os.File
	outputFile           *os.File
	metaFile             *os.File
	statusUpdatesFile    *os.File
	logFile              *os.File
	inputTargets         InputTargetsFunc
	outputResults        OutputResultsFunc
	customDNSNameservers []string // will be non-empty if user specified custom DNS, we'll check these are reachable before populating
	localAddrs           []net.IP // will be non-empty if user specified local addresses
	localPorts           []uint16 // will be non-empty if user specified local ports
	resolveIPv4          bool     // true if IPv4 is enabled, false if only IPv6 is enabled. Guaranteed to be set, whereas UserIPv4Choice may be nil if unset by the user
	resolveIPv6          bool
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
	config.ServerRateLimit = 100           // default rate limit for connections per second, overriden by CLI
	config.DNSServerRateLimit = 1_000
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

	// If user specifies nothing, default to IPv4
	// If only --use-ipv6 is set, => IPv6
	// if only --use-ipv4 is set, => IPv4
	// if both are set, => both IPv4 and IPv6
	// Cannot use neither IPv4 nor IPv6, for obvious reasons
	userSpecifiedUseIPv4 := config.UserIPv4Choice != nil && *config.UserIPv4Choice
	userSpecifiedUseIPv6 := config.UserIPv6Choice != nil && *config.UserIPv6Choice
	if !userSpecifiedUseIPv4 && !userSpecifiedUseIPv6 {
		// If both are unset, default to using IPv4
		config.resolveIPv4 = true
		config.resolveIPv6 = false
	} else if userSpecifiedUseIPv4 && !userSpecifiedUseIPv6 {
		// If only IPv4 is set, use IPv4
		config.resolveIPv4 = true
		config.resolveIPv6 = false
	} else if !userSpecifiedUseIPv4 && userSpecifiedUseIPv6 {
		// If only IPv6 is set, use IPv6
		config.resolveIPv4 = false
		config.resolveIPv6 = true
	} else {
		// If both are set, use both IPv4 and IPv6
		config.resolveIPv4 = true
		config.resolveIPv6 = true
	}

	// If localAddrString is set, parse it into a list of IP addresses to use for source IPs
	if config.LocalAddrString != "" {
		ips, err := extractIPAddresses(strings.Split(config.LocalAddrString, ","))
		if err != nil {
			log.Fatalf("could not extract IP addresses from address string %s: %s", config.LocalAddrString, err)
		}
		for _, ip := range ips {
			if ip == nil {
				log.Fatalf("could not extract IP addresses from address string: %s", config.LocalAddrString)
			}
		}
		config.localAddrs = ips
	}

	if !config.resolveIPv4 && !config.resolveIPv6 {
		log.Fatalf("must use either IPv4 or IPv6, or both. Use --use-ipv4 and/or --use-ipv6 to enable them.")
	}

	// Validate custom DNS must occur after setting resolveIPv4 and resolveIPv6
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
	// Initialize the DNS rate limiter
	// In an ideal world, this would be per-DNS server, but using the system DNS service (setting PreferGo on the resolver to false)
	// offers the benefit of using the OS DNS cache. The tradeoff is we don't get visibility into which DNS server is chosen for each request.
	// IMO, it's better to have a single rate limiter for all DNS requests than to not get DNS caching, so we'll use a single
	// user-configurable rate limiter for all DNS requests here. If a user uses more IPs, they can increase the rate limit accordingly.
	dnsRateLimiter = rate.NewLimiter(rate.Limit(config.DNSServerRateLimit), config.DNSServerRateLimit)
}

// GetMetaFile returns the file to which metadata should be output
func GetMetaFile() *os.File {
	return config.metaFile
}

func includeDebugOutput() bool {
	return config.Debug
}
