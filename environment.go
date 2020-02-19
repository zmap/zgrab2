package zgrab2

import (
	"bufio"
	"io"
	"sync"

	"github.com/sirupsen/logrus"
)

type InputSource struct {
	r io.Reader
}

func (in *InputSource) ReadInputsToChannel(ch chan<- ScanTarget) {
	GetTargetsCSV(in.r, ch)
}

type OutputDestination struct {
	w io.Writer
}

// WriteOutputsFromChannel reads from the provided channel and writes the output
// via the configured writer.
func (out *OutputDestination) WriteOutputsFromChannel(resultsChannel <-chan []byte) {
	buf := bufio.NewWriter(out.w)
	OutputResults(buf, resultsChannel)
}

type ScanWorkers struct {
	workerCount        int
	connectionsPerHost int
}

func (env *Environment) ScanTargets() {
	defer env.Done()
	for i, scanner := range env.Scanners {
		scanner.InitPerSender(i)
	}
	env.Logger.Debug("starting scanners")
	wg := sync.WaitGroup{}
	wg.Add(env.Workers.workerCount)
	for i := 0; i < env.Workers.workerCount; i++ {
		go func() {
			defer wg.Done()
			for t := range env.scanTargetChannel {
				env.Logger.Debugf("received scan target: %v", t)
				for run := 0; run < env.Workers.connectionsPerHost; run++ {
					for _, s := range env.Scanners {
						env.Logger.Debugf("scanning %v with scanner %v, execution %d", t, s, run)
						_, res := RunScanner(s, env.monitor, t)
						env.scanResponseChannel <- res
					}
				}
			}
		}()
	}
	// Encoders
	go func() {
		for range env.scanResponseChannel {
			// TODO
		}
		env.Logger.Debug("finished encoding results, closing output channel")
		close(env.encodedResultsChannel)
	}()
	env.Logger.Debug("started scanners, blocking until completion")
	wg.Wait()
	env.Logger.Debug("finished scanning, closing scan response channel")
	close(env.scanResponseChannel)
}

type Environment struct {
	Input    *InputSource
	Output   *OutputDestination
	Logger   *logrus.Logger
	Workers  *ScanWorkers
	Scanners []Scanner
	sync.WaitGroup

	scanTargetChannel     chan ScanTarget
	scanResponseChannel   chan ScanResponse
	encodedResultsChannel chan []byte
	monitor               *Monitor
}

func (env *Environment) Start() {
	env.scanTargetChannel = make(chan ScanTarget)
	env.scanResponseChannel = make(chan ScanResponse)
	env.encodedResultsChannel = make(chan []byte)
	env.Add(3)
	env.monitor = MakeMonitor(1, &env.WaitGroup)
	go env.WriteOutput()
	go env.ScanTargets()
	go env.ReadInput()
}

func (env *Environment) WriteOutput() {
	defer env.Done()
	env.Output.WriteOutputsFromChannel(env.encodedResultsChannel)
	env.Logger.Debug("finished writing output, stopping monitor")
	env.monitor.Stop()
}

func (env *Environment) ReadInput() {
	defer env.Done()
	env.Input.ReadInputsToChannel(env.scanTargetChannel)
	env.Logger.Debug("finished reading input, closing scan target channel")
	close(env.scanTargetChannel)
}
