package zgrab2

import (
	"encoding/json"
	"io"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"
)

type Grab struct {
	IP     string                      `json:"ip"`
	Domain string                      `json:"domain,omitempty"`
	Data   map[string]protocolResponse `json:"data,omitempty"`
}

// not good name, should change
type protocolResponse struct {
	Result         interface{} `json:"result,omitempty"`
	Error          *error      `json:"error,omitempty"`
	ErrorComponent string      `json:"error_component,omitempty"`
}

// GrabWorker calls handler for each action
func RunGrabWorker(input interface{}) []byte {
	protocolResult := make(map[string]protocolResponse)

	for _, action := range lookups {
		name, res := makeHandler(action)
		protocolResult[name] = res
		if res.Error != nil && !config.Mult.ContinueOnError {
			break
		}
	}

	strInput, _ := input.(string)
	a := Grab{IP: strInput, Domain: strInput, Data: protocolResult}
	result, _ := json.Marshal(a)

	return result
}

// Process sets up an output encoder, input reader, and starts grab workers
func Process(out io.Writer, mon Monitor) {
	workers := config.Senders
	processQueue := make(chan interface{}, workers*4)
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
	for {
		for i := 0; i < 2; i++ {
			processQueue <- strconv.Itoa(i)
		}

		break

	}

	close(processQueue)
	workerDone.Wait()
	close(outputQueue)
	outputDone.Wait()
}
