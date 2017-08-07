package zgrab2

// Monitor
type Monitor struct {
	successes uint
	failures  uint
	statuses  chan status
}

type status uint

const (
	status_success status = iota
	status_failure status = iota
)

func (m *Monitor) Successes() uint {
	return m.successes
}

func (m *Monitor) Failures() uint {
	return m.failures
}

func (m *Monitor) Total() uint {
	return m.successes + m.failures
}

func (m *Monitor) Done() {
	close(m.statuses)
}

func MakeMonitor() *Monitor {
	m := new(Monitor)
	m.statuses = make(chan status, config.Senders*4)
	go func() {
		for s := range m.statuses {
			switch s {
			case status_success:
				m.successes++
			case status_failure:
				m.failures++
			default:
				continue
			}
		}
	}()
	return m
}
