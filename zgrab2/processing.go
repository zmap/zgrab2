package zgrab2

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"io"
	"strconv"
	"sync"
)

type Grab struct {
	IP     string                      `json:"ip"`
	Domain string                      `json:"domain"`
	Data   map[string]protocolResponse `json:"data"`
}

type Handler func(interface{}) interface{}

// not good name, should change
type protocolResponse struct {
	result interface{}
	err    error
}

// GrabWorker divides up input and sends to each handler and then consolidates at end
func RunGrabWorker(input interface{}) []byte {
	protocolResult := make(map[string]protocolResponse)

	for _, action := range lookups {
		name, res := makeHandler(action)
		protocolResult[name] = res
		if res.err != nil && !options.Mult.ContinueOnError {
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
	workers := options.Senders
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
