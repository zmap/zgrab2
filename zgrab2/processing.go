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
	IP     *string                     `json:"ip,omitempty"`
	Domain string                      `json:"domain,omitempty"`
	Data   map[string]protocolResponse `json:"data,omitempty"`
}

type grabTarget struct {
	IP     net.IP
	Domain string
}

// not good name, should change
type protocolResponse struct {
	Result         interface{} `json:"result,omitempty"`
	Error          *error      `json:"error,omitempty"`
	ErrorComponent string      `json:"error_component,omitempty"`
}

// GrabWorker calls handler for each action
func RunGrabWorker(input grabTarget) []byte {
	protocolResult := make(map[string]protocolResponse)

	for _, action := range lookups {
		name, res := makeHandler(action)
		protocolResult[name] = res
		if res.Error != nil && !config.Mult.ContinueOnError {
			break
		}
	}

	var ipstr *string
	if input.IP.String() == "<nil>" {
		ipstr = nil
	} else {
		s := input.IP.String()
		ipstr = &s
	}

	a := Grab{IP: ipstr, Domain: input.Domain, Data: protocolResult}
	result, err := json.Marshal(a)
	if err != nil {
		log.Fatal(err)
	}

	return result
}

// Process sets up an output encoder, input reader, and starts grab workers
func Process(out io.Writer, mon Monitor) {
	workers := config.Senders
	processQueue := make(chan grabTarget, workers*4)
	outputQueue := make(chan []byte, workers*4) //what is the magic 4?

	//Create wait groups
	var workerDone sync.WaitGroup
	var outputDone sync.WaitGroup
	workerDone.Add(int(workers))
	outputDone.Add(1)

	// Start the output encoder
	go func() {
		for result := range outputQueue {
			if _, err := out.Write(result); err != nil {
				log.Fatal(err.Error())
			}
			if _, err := out.Write([]byte("\n")); err != nil {
				log.Fatal(err.Error())
			}
		}
		outputDone.Done()
	}()
	//Start all the workers
	for i := 0; i < workers; i++ {
		go func() {
			for obj := range processQueue {
				//divide up, run, consolidate
				result := RunGrabWorker(obj)
				outputQueue <- result
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
		} else {
			if domain == "" {
				for _, ip := range ipnet {
					processQueue <- grabTarget{IP: ip}
				}
			} else {
				processQueue <- grabTarget{Domain: domain}
			}
		}
	}

	close(processQueue)
	workerDone.Wait()
	close(outputQueue)
	outputDone.Wait()
}
