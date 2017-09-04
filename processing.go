package zgrab2

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

type Grab struct {
	IP     string                    `json:"ip,omitempty"`
	Domain string                    `json:"domain,omitempty"`
	Data   map[string]ModuleResponse `json:"data,omitempty"`
}

type target struct {
	IP     net.IP
	Domain string
}

type ModuleResponse struct {
	Result         interface{} `json:"result,omitempty"`
	Time           string      `json:"time,omitempty"`
	Error          *error      `json:"error,omitempty"`
	ErrorComponent string      `json:"error_component,omitempty"`
}

// grabTarget calls handler for each action
func grabTarget(input target, m *Monitor) []byte {
	moduleResult := make(map[string]ModuleResponse)

	for _, moduleName := range orderedModules {
		module := modules[moduleName]
		name, res := RunModule(*module, m, input.IP)
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
	processQueue := make(chan target, workers*4)
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
		go func() {
			for obj := range processQueue {
				for run := uint(0); run < config.ConnectionsPerHost; run++ {
					result := grabTarget(obj, mon)
					outputQueue <- result
				}
			}
			workerDone.Done()
		}()
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
		st := string(obj)
		ipnet, domain, err := ParseInput(st[:len(st)-1]) //remove newline
		if err != nil {
			log.Error(err)
			continue
		}
		var ip net.IP
		if ipnet != nil {
			if ipnet.Mask != nil {
				for ip = ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
					processQueue <- target{IP: duplicateIP(ip), Domain: domain}
				}
				continue
			} else {
				ip = ipnet.IP
			}
		}
		processQueue <- target{IP: ip, Domain: domain}
	}

	close(processQueue)
	workerDone.Wait()
	close(outputQueue)
	outputDone.Wait()
}
