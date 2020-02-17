package zgrab2

import (
	"io"
	"sync"
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

func (out *OutputDestination) WriteOutputsFromChannel() {

}

type Environment struct {
	Input  *InputSource
	Output *OutputDestination
	sync.WaitGroup

	scanTargetChannel chan ScanTarget
}

func (env *Environment) Start() {
	env.scanTargetChannel = make(chan ScanTarget)
	env.Add(2)
	go env.ReadInput()
	go env.WriteOutput()
	go func() {
		for range env.scanTargetChannel {
			// Scanning not yet implemented
		}
	}()
}

func (env *Environment) WriteOutput() {
	env.Output.WriteOutputsFromChannel()
	defer env.Done()
}

func (env *Environment) ReadInput() {
	defer env.Done()
	env.Input.ReadInputsToChannel(env.scanTargetChannel)
	close(env.scanTargetChannel)
}
