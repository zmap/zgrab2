package zgrab2

// Monitor
type Monitor struct {
	successes uint
	failures  uint
	statuses  chan status

	//need to put config here...but options struct is in main
	//do we need a config? don't need if runCount is only use
}

type status uint

const (
	status_success status = iota
	status_failure status = iota
)

func (m *Monitor) Success() uint {
	return m.successes
}

func (m *Monitor) Failure() uint {
	return m.failures
}

func (m *Monitor) Total() uint {
	return m.successes + m.failures
}

func (m *Monitor) Done() {
	close(m.statuses)
}

func MakeMonitor() Monitor {
	m := new(Monitor)
	m.statuses = make(chan status, config.Senders*4)
	/* you can uncomment this when you get your shit together
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
	}() */
	return *m
}
