package smtp

import "sync"

type Metadata struct {
	sync.Mutex
	HostsSupportingEHLO     uint `json:"hosts_supporting_ehlo"`
	HostsSupportingHELO     uint `json:"hosts_supporting_helo"`
	HostsSupportingSTARTTLS uint `json:"hosts_supporting_starttls"`
}

var moduleMetadata Metadata

func init() {
	moduleMetadata = Metadata{}
	moduleMetadata.Mutex = sync.Mutex{}
}

func (m *Metadata) incrementHostsSupportingEHLO() {
	m.Lock()
	defer m.Unlock()
	m.HostsSupportingEHLO++
}

func (m *Metadata) incrementHostsSupportingHELO() {
	m.Lock()
	defer m.Unlock()
	m.HostsSupportingHELO++
}

func (m *Metadata) incrementHostsSupportingSTARTTLS() {
	m.Lock()
	defer m.Unlock()
	m.HostsSupportingSTARTTLS++
}
