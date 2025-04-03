package zgrab2

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zmap/zcrypto/tls"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2/lib/output"
)

// Grab contains all scan responses for a single host
type Grab struct {
	IP     string                  `json:"ip,omitempty"`
	Port   uint                    `json:"port,omitempty"`
	Domain string                  `json:"domain,omitempty"`
	Data   map[string]ScanResponse `json:"data,omitempty"`
}

// ScanTarget is the host that will be scanned
type ScanTarget struct {
	IP     net.IP
	Domain string
	Tag    string
	Port   uint
}

func (target ScanTarget) String() string {
	if target.IP == nil && target.Domain == "" {
		return "<empty target>"
	}
	res := ""
	if target.IP != nil && target.Domain != "" {
		res = target.Domain + "(" + target.IP.String() + ")"
	} else if target.IP != nil {
		res = target.IP.String()
	} else {
		res = target.Domain
	}
	if target.Tag != "" {
		res += " tag:" + target.Tag
	}
	return res
}

// Host gets the host identifier as a string: the IP address if it is available,
// or the domain if not.
func (target *ScanTarget) Host() string {
	if target.IP != nil {
		return target.IP.String()
	} else if target.Domain != "" {
		return target.Domain
	}
	log.Fatalf("Bad target %s: no IP/Domain", target.String())
	panic("unreachable")
}

// GetDefaultTCPDialer returns a TCP dialer suitable for modules with default TCP behavior
func GetDefaultTCPDialer(flags *BaseFlags) func(ctx context.Context, t *ScanTarget) (net.Conn, error) {
	dialer := NewDialer(nil)
	dialer.Timeout = flags.Timeout
	return func(ctx context.Context, t *ScanTarget) (net.Conn, error) {
		var port uint
		// If the port is supplied in ScanTarget, let that override the cmdline option
		if t.Port != 0 {
			port = t.Port
		} else {
			port = flags.Port
		}
		if deadline, ok := ctx.Deadline(); ok {
			dialer.Dialer.Deadline = deadline
		}
		address := net.JoinHostPort(t.Host(), fmt.Sprintf("%d", port))
		return dialer.DialContext(ctx, "tcp", address)
	}
}

func getPerTargetDefaultTCPDialer(flags *BaseFlags) func(scanTarget *ScanTarget) func(ctx context.Context, network, target string) (net.Conn, error) {
	return func(scanTarget *ScanTarget) func(ctx context.Context, network, target string) (net.Conn, error) {
		dialer := NewDialer(nil)
		dialer.Timeout = flags.Timeout
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			switch network {
			case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
				// If the scan is for a specific IP, and a domain name is provided, we
				// don't want to just let the http library resolve the domain.  Create
				// a fake resolver that we will use, that always returns the IP we are
				// given to scan.
				if scanTarget.IP != nil && scanTarget.Domain != "" {
					host, _, err := net.SplitHostPort(addr)
					if err != nil {
						log.Errorf("http/scanner.go dialContext: unable to split host:port '%s'", addr)
						log.Errorf("No fake resolver, IP address may be incorrect: %s", err)
					} else {
						// In the case of redirects, we don't want to blindly use the
						// IP we were given to scan, however.  Only use the fake
						// resolver if the domain originally specified for the scan
						// target matches the current address being looked up in this
						// DialContext.
						if host == scanTarget.Domain {
							resolver, err := NewFakeResolver(scanTarget.IP.String())
							if err != nil {
								return nil, err
							}
							dialer.Dialer.Resolver = resolver
						}
					}
				}
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return conn, nil
		}
	}
}

// GetDefaultTLSDialer returns a TLS-over-TCP dialer suitable for modules with default TLS behavior
func GetDefaultTLSDialer(flags *BaseFlags, tlsFlags *TLSFlags) func(ctx context.Context, t *ScanTarget) (net.Conn, error) {
	return func(ctx context.Context, t *ScanTarget) (net.Conn, error) {
		l4Conn, err := GetDefaultTCPDialer(flags)(ctx, t)
		if err != nil {
			return nil, fmt.Errorf("could not initiate a L4 connection with L4 dialer: %v", err)
		}
		return GetDefaultTLSWrapper(tlsFlags)(ctx, t, l4Conn)
	}
}

// GetDefaultTLSWrapper uses the TLS flags to create a wrapper that upgrades a TCP connection to a TLS connection.
func GetDefaultTLSWrapper(tlsFlags *TLSFlags) func(ctx context.Context, t *ScanTarget, conn net.Conn) (*TLSConnection, error) {
	return func(ctx context.Context, t *ScanTarget, conn net.Conn) (*TLSConnection, error) {
		tlsConfig, err := tlsFlags.GetTLSConfigForTarget(t)
		if err != nil {
			return nil, fmt.Errorf("could not get tls config for target %s: %w", t.String(), err)
		}
		// Set SNI server name on redirects unless --server-name was used (issue #300)
		//  - t.Domain is always set to the *original* Host so it's not useful for setting SNI
		//  - host is the current target of the request in this context; this is true for the
		//    initial request as well as subsequent requests caused by redirects
		//  - scan.scanner.config.ServerName is the value from --server-name if one was specified

		// If SNI is enabled and --server-name is not set, use the target host for the SNI server name
		if !tlsFlags.NoSNI && tlsFlags.ServerName == "" {
			host := t.Domain
			// RFC4366: Literal IPv4 and IPv6 addresses are not permitted in "HostName"
			if i := net.ParseIP(host); i == nil {
				tlsConfig.ServerName = host
			}
		}
		tlsConn := TLSConnection{
			Conn:  *(tls.Client(conn, tlsConfig)),
			flags: tlsFlags,
		}
		err = tlsConn.Handshake()
		if err != nil {
			return nil, fmt.Errorf("could not perform tls handshake for target %s: %w", t.String(), err)
		}
		return &tlsConn, err
	}
}

// GetDefaultUDPDialer returns a UDP dialer suitable for modules with default UDP behavior
func GetDefaultUDPDialer(flags *BaseFlags, udp *UDPFlags) func(ctx context.Context, t *ScanTarget) (net.Conn, error) {
	dialer := NewDialer(nil)
	dialer.Timeout = flags.Timeout
	return func(ctx context.Context, t *ScanTarget) (net.Conn, error) {
		address := net.JoinHostPort(t.Host(), fmt.Sprintf("%d", t.Port))
		var local *net.UDPAddr
		if udp != nil && (udp.LocalAddress != "" || udp.LocalPort != 0) {
			local = &net.UDPAddr{}
			if udp.LocalAddress != "" && udp.LocalAddress != "*" {
				local.IP = net.ParseIP(udp.LocalAddress)
				if local.IP == nil {
					// local address provided is invalid
					return nil, fmt.Errorf("could not parse local address %s", udp.LocalAddress)
				}
			}
			if udp.LocalPort != 0 {
				local.Port = int(udp.LocalPort)
			}
		}
		dialer.Dialer.LocalAddr = local
		return dialer.DialContext(ctx, "udp", address)
	}
}

// BuildGrabFromInputResponse constructs a Grab object for a target, given the
// scan responses.
func BuildGrabFromInputResponse(t *ScanTarget, responses map[string]ScanResponse) *Grab {
	var ipstr string
	if t.IP != nil {
		ipstr = t.IP.String()
	}
	return &Grab{
		IP:     ipstr,
		Port:   t.Port,
		Domain: t.Domain,
		Data:   responses,
	}
}

// EncodeGrab serializes a Grab to JSON, handling the debug fields if necessary.
func EncodeGrab(raw *Grab, includeDebug bool) ([]byte, error) {
	var outputData any
	if includeDebug {
		outputData = raw
	} else {
		// If the caller doesn't explicitly request debug data, strip it out.
		// TODO: Migrate this to the ZMap fork of sheriff, once it's more
		// stable.
		processor := output.Processor{Verbose: false}
		stripped, err := processor.Process(raw)
		if err != nil {
			log.Debugf("Error processing results: %v", err)
			stripped = raw
		}
		outputData = stripped
	}
	return json.Marshal(outputData)
}

// grabTarget calls handler for each action
func grabTarget(input ScanTarget, m *Monitor) []byte {
	moduleResult := make(map[string]ScanResponse)

	for _, scannerName := range orderedScanners {
		scanner := scanners[scannerName]
		trigger := (*scanner).GetTrigger()
		if input.Tag != trigger {
			continue
		}
		defer func(name string) {
			if e := recover(); e != nil {
				log.Errorf("Panic on scanner %s when scanning target %s: %#v", scannerName, input.String(), e)
				// Bubble out original error (with original stack) in lieu of explicitly logging the stack / error
				panic(e)
			}
		}(scannerName)
		name, res := RunScanner(*scanner, m, input)
		moduleResult[name] = res
		if res.Error != nil && !config.Multiple.ContinueOnError {
			break
		}
		if res.Status == SCAN_SUCCESS && config.Multiple.BreakOnSuccess {
			break
		}
	}

	raw := BuildGrabFromInputResponse(&input, moduleResult)
	result, err := EncodeGrab(raw, includeDebugOutput())
	if err != nil {
		log.Errorf("unable to marshal data: %s", err)
	}

	return result
}

// Process sets up an output encoder, input reader, and starts grab workers.
func Process(mon *Monitor) {
	workers := config.Senders
	processQueue := make(chan ScanTarget, workers*4)
	outputQueue := make(chan []byte, workers*4)

	//Create wait groups
	var workerDone sync.WaitGroup
	var outputDone sync.WaitGroup
	workerDone.Add(int(workers))
	outputDone.Add(1)

	// Start the output encoder
	go func() {
		defer outputDone.Done()
		if err := config.outputResults(outputQueue); err != nil {
			log.Fatal(err)
		}
	}()
	//Start all the workers
	for i := 0; i < workers; i++ {
		go func(i int) {
			for _, scannerName := range orderedScanners {
				scanner := *scanners[scannerName]
				scanner.InitPerSender(i)
			}
			for obj := range processQueue {
				for run := uint(0); run < uint(config.ConnectionsPerHost); run++ {
					result := grabTarget(obj, mon)
					outputQueue <- result
				}
			}
			workerDone.Done()
		}(i)
	}

	if err := config.inputTargets(processQueue); err != nil {
		log.Fatal(err)
	}
	close(processQueue)
	workerDone.Wait()
	close(outputQueue)
	outputDone.Wait()
}
