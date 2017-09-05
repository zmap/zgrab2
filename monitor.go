package zgrab2

// Monitor
type monitor struct {
	states       map[string]*State
	statusesChan chan moduleStatus
}

// State contains the number of successes and failures for a given module
type State struct {
	// Successes is the number of hosts that had successful grabs
	Successes uint `json:"successes"`

	// Failures is the number of hosts that had errors
	Failures uint `json:"failures"`
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

// GetStatuses returns a map from module name to State of that module
func (m *monitor) GetStatuses() map[string]*State {
	return m.states
}

// MakeMonitor creates and returns the monitor that will track the number
// of successes and failures for each module
func MakeMonitor() *monitor {
	m := new(monitor)
	m.statusesChan = make(chan moduleStatus, config.Senders*4)
	m.states = make(map[string]*State, 10)
	go func() {
		for s := range m.statusesChan {
			if m.states[s.name] == nil {
				m.states[s.name] = new(State)
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
