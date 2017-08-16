package zgrab2

// Monitor
type Monitor struct {
	states       map[string]*state
	statusesChan chan moduleStatus
}

type state struct {
	successes uint
	failures  uint
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

func (m *Monitor) GetStatuses() map[string]*state {
	return m.states
}

func MakeMonitor() *Monitor {
	m := new(Monitor)
	m.statusesChan = make(chan moduleStatus, config.Senders*4)
	m.states = make(map[string]*state, 10)
	go func() {
		for s := range m.statusesChan {
			if m.states[s.name] == nil {
				m.states[s.name] = new(state)
			}
			switch s.st {
			case status_success:
				m.states[s.name].successes++
			case status_failure:
				m.states[s.name].failures++
			default:
				continue
			}
		}
	}()
	return m
}
