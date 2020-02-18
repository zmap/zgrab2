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

type Environment struct {
	Input  *InputSource
	Output *OutputDestination
	Logger *logrus.Logger
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
	go env.ReadInput()
	go env.WriteOutput()
	go func() {
		defer env.Done()
		for t := range env.scanTargetChannel {
			// Scanning not yet implemented
			env.Logger.Debugf("received scan target: %v", t)
		}
		env.Logger.Debug("finished scanning, closing output channel")
		close(env.encodedResultsChannel)
	}()
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
