package zgrab2

// Monitor
type Monitor struct {
	states       map[string]*State
	statusesChan chan moduleStatus
}

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
	status_success status = iota
	status_failure status = iota
)

func (m *Monitor) GetStatuses() map[string]*State {
	return m.states
}

func MakeMonitor() *Monitor {
	m := new(Monitor)
	m.statusesChan = make(chan moduleStatus, config.Senders*4)
	m.states = make(map[string]*State, 10)
	go func() {
		for s := range m.statusesChan {
			if m.states[s.name] == nil {
				m.states[s.name] = new(State)
			}
			switch s.st {
			case status_success:
				m.states[s.name].Successes++
			case status_failure:
				m.states[s.name].Failures++
			default:
				continue
			}
		}
	}()
	return m
}
