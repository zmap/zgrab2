package zgrab2

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Grab contains all scan responses for a single host
type Grab struct {
	IP     string                  `json:"ip,omitempty"`
	Domain string                  `json:"domain,omitempty"`
	Data   map[string]ScanResponse `json:"data,omitempty"`
}

// ScanTarget is the host that will be scanned
type ScanTarget struct {
	IP     net.IP
	Domain string
}

func (target ScanTarget) String() string {
	if target.IP == nil && target.Domain == "" {
		return "<empty target>"
	} else if target.IP != nil && target.Domain != "" {
		return target.Domain + "(" + target.IP.String() + ")"
	} else if target.IP != nil {
		return target.IP.String()
	}
	return target.Domain
}

// Open connects to the ScanTarget using the configured flags, and returns a net.Conn that uses the configured timeouts for Read/Write operations.
func (target *ScanTarget) Open(flags *BaseFlags) (net.Conn, error) {
	timeout := time.Second * time.Duration(flags.Timeout)
	address := fmt.Sprintf("%s:%d", target.IP.String(), flags.Port)
	return DialTimeoutConnection("tcp", address, timeout)
}

// grabTarget calls handler for each action
func grabTarget(input ScanTarget, m *Monitor) []byte {
	moduleResult := make(map[string]ScanResponse)

	for _, scannerName := range orderedScanners {
		defer func(name string) {
			if e := recover(); e != nil {
				log.Errorf("Panic on scanner %s when scanning target %s", scannerName, input.String())
				// Bubble out original error (with original stack) in lieu of explicitly logging the stack / error
				panic(e)
			}
		}(scannerName)
		scanner := scanners[scannerName]
		name, res := RunScanner(*scanner, m, input)
		moduleResult[name] = res
		if res.Error != nil && !config.Multiple.ContinueOnError {
			break
		}
	}

	var ipstr string
	if input.IP == nil {
		ipstr = ""
	} else {
		s := input.IP.String()
		ipstr = s
	}

	a := Grab{IP: ipstr, Domain: input.Domain, Data: moduleResult}
	result, err := json.Marshal(a)
	if err != nil {
		log.Fatalf("unable to marshal data: %s", err)
	}

	return result
}

// Process sets up an output encoder, input reader, and starts grab workers
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
		out := bufio.NewWriter(config.outputFile)
		defer outputDone.Done()
		defer out.Flush()
		for result := range outputQueue {
			if _, err := out.Write(result); err != nil {
				log.Fatal(err)
			}
			if err := out.WriteByte('\n'); err != nil {
				log.Fatal(err)
			}
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

	// Read the input, send to workers
	input := bufio.NewReader(config.inputFile)
	for {
		obj, err := input.ReadBytes('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			log.Error(err)
		}
		st := strings.TrimSpace(string(obj))
		ipnet, domain, err := ParseTarget(st)
		if err != nil {
			log.Error(err)
			continue
		}
		var ip net.IP
		if ipnet != nil {
			if ipnet.Mask != nil {
				for ip = ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
					processQueue <- ScanTarget{IP: duplicateIP(ip), Domain: domain}
				}
				continue
			} else {
				ip = ipnet.IP
			}
		}
		processQueue <- ScanTarget{IP: ip, Domain: domain}
	}

	close(processQueue)
	workerDone.Wait()
	close(outputQueue)
	outputDone.Wait()
}
