package zgrab2

// Monitor is a collection of states per scans and a channel to communicate
// those scans to the monitor
type Monitor struct {
	states       map[string]*State
	statusesChan chan moduleStatus
	// Callback is invoked after each scan.
	Callback     func(string)
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

// MakeMonitor returns a Monitor object that can be used to collect and send
// the status of a running scan
func MakeMonitor() *Monitor {
	m := new(Monitor)
	m.statusesChan = make(chan moduleStatus, config.Senders*4)
	m.states = make(map[string]*State, 10)
	go func() {
		for s := range m.statusesChan {
			if m.states[s.name] == nil {
				m.states[s.name] = new(State)
			}
			if m.Callback != nil {
				m.Callback(s.name)
			}
			switch s.st {
			case statusSuccess:
				m.states[s.name].Successes++
			case statusFailure:
				m.states[s.name].Failures++
			default:
				continue
			}
		}
	}()
	return m
}
