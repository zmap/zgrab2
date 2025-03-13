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
	return func(ctx context.Context, t *ScanTarget) (net.Conn, error) {
		var port uint
		// If the port is supplied in ScanTarget, let that override the cmdline option
		if t.Port != 0 {
			port = t.Port
		} else {
			port = flags.Port
		}

		address := net.JoinHostPort(t.Host(), fmt.Sprintf("%d", port))
		return DialTimeoutConnection(ctx, "tcp", address, flags.Timeout, flags.BytesReadLimit)
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
		config, err := tlsFlags.GetTLSConfigForTarget(t)
		if err != nil {
			return nil, fmt.Errorf("could not get tls config for target %s: %w", t.String(), err)
		}
		tlsConn := TLSConnection{
			Conn:  *(tls.Client(conn, config)),
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
	return func(ctx context.Context, t *ScanTarget) (net.Conn, error) {
		var port uint
		// If the port is supplied in ScanTarget, let that override the cmdline option
		if t.Port != 0 {
			port = t.Port
		} else {
			port = flags.Port
		}

		address := net.JoinHostPort(t.Host(), fmt.Sprintf("%d", port))
		var local *net.UDPAddr
		if udp != nil && (udp.LocalAddress != "" || udp.LocalPort != 0) {
			local = &net.UDPAddr{}
			if udp.LocalAddress != "" && udp.LocalAddress != "*" {
				local.IP = net.ParseIP(udp.LocalAddress)
			}
			if udp.LocalPort != 0 {
				local.Port = int(udp.LocalPort)
			}
		}
		remote, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
		conn, err := net.DialUDP("udp", local, remote)
		if err != nil {
			return nil, err
		}
		return NewTimeoutConnection(ctx, conn, flags.Timeout, 0, 0, flags.BytesReadLimit), nil
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
