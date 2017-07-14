package zlib

import (
	"encoding/json"
	//log "github.com/sirupsen/logrus"
	//"fmt"
	"io"
	"strconv"
	"sync"
)

type Output struct {
	IP     string                 `json:"ip"`
	Domain string                 `json:"domain"`
	Data   map[string]interface{} `json:"data"`
}

type Demo struct {
	Port     int    `json:"port"`
	Endpoint string `json:"endpoint'`
}

type Worker interface {
	MakeHandler() Handler
	Success() uint
	Failure() uint
	Total() uint
	Done()
	RunCount() uint
}

type Handler func(interface{}) interface{}

// not good name, should change
type protocolResponse struct {
	protocol string
	result   interface{}
}

// handler for demo purposes
// handler will marshal and send a single protocol response to the controller
func handler(bufChan chan protocolResponse) {
	r := protocolResponse{protocol: "http"}
	t := Demo{Port: 22, Endpoint: "/"}
	r.result = t
	bufChan <- r
	r = protocolResponse{protocol: "ssh"}
	t = Demo{Port: 80, Endpoint: "oops"}
	r.result = t
	bufChan <- r
}

// Controller divides up input to each handler and then consolidates at end
func Controller(input interface{}, numProtocols uint) []byte {
	bufChan := make(chan protocolResponse, numProtocols)

	protocolResult := make(map[string]interface{})

	for i := 0; uint(i) < numProtocols; i++ {
		go handler(bufChan)
	}

	for i := 0; uint(i) < numProtocols; i++ {
		select {
		case msg := <-bufChan:
			//receive from bufChan
			protocolResult[msg.protocol] = msg.result
		}
	}

	strInput, _ := input.(string)
	a := Output{IP: strInput, Domain: strInput, Data: protocolResult}
	result, _ := json.Marshal(a)

	return result
}

// Process sets up an output encoder, input reader, and starts grab workers
func Process(out io.Writer, workers uint, numProtocols uint) {
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
				panic(err.Error())
			}
			if _, err := out.Write([]byte("\n")); err != nil {
				panic(err.Error())
			}
		}
		outputDone.Done()
	}()

	//Start all the workers
	for i := uint(0); i < workers; i++ {
		go func() {
			for obj := range processQueue {
				//divide up, run, consolidate
				result := Controller(obj, numProtocols)
				outputQueue <- result
			}
			workerDone.Done()
		}()
	}

	// Read the input, send to workers
	for {
		for i := 0; i < 10; i++ {
			processQueue <- strconv.Itoa(i)
		}

		break

	}

	close(processQueue)
	workerDone.Wait()
	close(outputQueue)
	outputDone.Wait()
}
