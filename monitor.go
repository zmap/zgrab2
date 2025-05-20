package zgrab2

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Monitor is a collection of states per scans and a channel to communicate
// those scans to the monitor
type Monitor struct {
	startTime      time.Time // time when the monitor started
	totalSuccesses uint      // number of successful scans across modules
	totalFailures  uint      // number of failed scans across modules
	states         map[string]*State
	statusesChan   chan moduleStatus
	// Callback is invoked after each scan.
	Callback func(string)
}

// State contains the respective number of successes and failures
// for a given scan
type State struct {
	Successes uint `json:"successes"`
	Failures  uint `json:"failures"`
}

type moduleStatus struct {
	name string
	st   status
}

type status uint

const (
	statusSuccess status = iota
	statusFailure status = iota
)

// GetStatuses returns a mapping from scanner names to the current number
// of successes and failures for that scanner
func (m *Monitor) GetStatuses() map[string]*State {
	return m.states
}

// Stop indicates the monitor is done and the internal channel should be closed.
// This function does not block, but will allow a call to Wait() on the
// WaitGroup passed to MakeMonitor to return.
func (m *Monitor) Stop() {
	close(m.statusesChan)
}

func (m *Monitor) printStatus(isFinalPrint bool) {
	if config.statusUpdatesFile == nil {
		return // no file to write to
	}
	scanStatusMsg := ""
	if isFinalPrint {
		scanStatusMsg = "Scan Complete; "
	}
	timeSinceStart := time.Since(m.startTime)
	scanRate := float64(0)
	if timeSinceStart.Seconds() > 0 {
		scanRate = float64(m.totalSuccesses+m.totalFailures) / timeSinceStart.Seconds() // avoid division by zero
	}
	scanSuccessRate := float64(0)
	totalTargetsScanned := m.totalSuccesses + m.totalFailures
	if totalTargetsScanned > 0 {
		scanSuccessRate = float64(m.totalSuccesses) / float64(totalTargetsScanned) * 100
	}
	updateLine := fmt.Sprintf("%02dh:%02dm:%02ds; %s%d targets scanned; %.02f targets/sec; %.01f%% success rate",
		int(timeSinceStart.Hours()),
		int(timeSinceStart.Minutes())%60,
		int(timeSinceStart.Seconds())%60,
		scanStatusMsg,
		m.totalSuccesses+m.totalFailures,
		scanRate,
		scanSuccessRate,
	)
	_, err := fmt.Fprintln(config.statusUpdatesFile, updateLine)
	if err != nil {
		log.Errorf("unable to write periodic status update: %v", err)
	}
}

// MakeMonitor returns a Monitor object that can be used to collect and send
// the status of a running scan
func MakeMonitor(statusChanSize int, wg *sync.WaitGroup) *Monitor {
	m := new(Monitor)
	m.statusesChan = make(chan moduleStatus, statusChanSize)
	m.states = make(map[string]*State, 10)
	m.startTime = time.Now()
	wg.Add(1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer wg.Done()
		for {
			select {
			case s, ok := <-m.statusesChan:
				if !ok {
					// channel closed, exiting
					ticker.Stop()
					m.printStatus(true) // print final status
					return
				}
				// process new status
				if m.states[s.name] == nil {
					m.states[s.name] = new(State)
				}
				if m.Callback != nil {
					m.Callback(s.name)
				}
				switch s.st {
				case statusSuccess:
					m.states[s.name].Successes++
					m.totalSuccesses++
				case statusFailure:
					m.states[s.name].Failures++
					m.totalFailures++
				default:
					continue
				}
			case <-ticker.C:
				// print per-second summary
				m.printStatus(false)
			}
		}
	}()
	return m
}
