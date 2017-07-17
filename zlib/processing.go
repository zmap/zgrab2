package zlib

import (
	"encoding/json"
	//log "github.com/sirupsen/logrus"
	//"fmt"
	"io"
	//"net"
	"strconv"
	"sync"
)

type Grab struct {
	IP     string                 `json:"ip"`
	Domain string                 `json:"domain"`
	Data   map[string]interface{} `json:"data"`
}

type Demo struct {
	Port     int    `json:"port"`
	Endpoint string `json:"endpoint'`
}

type Demo1 struct {
	Test string `json:"test"`
	What string `json:"what"`
}

type Handler func(interface{}) interface{}

// not good name, should change
type protocolResponse struct {
	protocol string
	result   interface{}
}

// handler for demo purposes
// handler will marshal and send a single protocol response to the worker
func handler(bufChan chan protocolResponse) {
	r := protocolResponse{protocol: "http"}
	t := Demo{Port: 22, Endpoint: "/"}
	r.result = t
	bufChan <- r
	r = protocolResponse{protocol: "tls"}
	v := Demo1{Test: "eff", What: "oh"}
	r.result = v
	bufChan <- r
	r = protocolResponse{protocol: "ssh"}
	t = Demo{Port: 80, Endpoint: "oops"}
	r.result = t
	bufChan <- r
}

// GrabWorker divides up input and sends to each handler and then consolidates at end
func GrabWorker(input interface{}) []byte {
	bufChan := make(chan protocolResponse, NumProtocols)

	protocolResult := make(map[string]interface{})

	for i := 0; i < NumProtocols; i++ {
		go handler(bufChan)
	}

	for i := 0; i < NumProtocols; i++ {
		select {
		case msg := <-bufChan:
			//receive from bufChan
			protocolResult[msg.protocol] = msg.result
		}
	}

	strInput, _ := input.(string)
	a := Grab{IP: strInput, Domain: strInput, Data: protocolResult}
	result, _ := json.Marshal(a)

	return result
}

// Process sets up an output encoder, input reader, and starts grab workers
func Process(out io.Writer, con Controller) {
	workers := Options[0].Senders
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
	for i := 0; i < workers; i++ {
		go func() {
			for obj := range processQueue {
				//divide up, run, consolidate
				result := GrabWorker(obj)
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
