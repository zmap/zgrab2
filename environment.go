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
	scanners           []Scanner
	workerCount        int
	connectionsPerHost int
}

func (env *Environment) ScanTargets() {
	defer env.Done()
	for i, scanner := range env.Scans.scanners {
		scanner.InitPerSender(i)
	}
	wg := sync.WaitGroup{}
	wg.Add(env.Scans.workerCount)
	for i := 0; i < env.Scans.workerCount; i++ {
		go func() {
			defer wg.Done()
			for t := range env.scanTargetChannel {
				env.Logger.Debugf("received scan target: %v", t)
				for run := 0; run < env.Scans.connectionsPerHost; run++ {
					for _, s := range env.Scans.scanners {
						env.Logger.Debugf("scanning %v with scanner %v, execution %d", t, s, run)
					}
				}
			}
		}()
	}
	env.Logger.Debug("started scanners, blocking until targets are completed")
	wg.Wait()
	env.Logger.Debug("finished scanning, closing output channel")
	close(env.encodedResultsChannel)
}

type Environment struct {
	Input  *InputSource
	Output *OutputDestination
	Logger *logrus.Logger
	Scans  *ScanWorkers
	sync.WaitGroup

	scanTargetChannel     chan ScanTarget
	encodedResultsChannel chan []byte
	monitor               *Monitor
}

func (env *Environment) Start() {
	env.scanTargetChannel = make(chan ScanTarget)
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
