package siemens

// S7Log is the output type for the Siemens S7 scan.
type S7Log struct {
	// IsS7 indicates that S7 was actually detected, so it should always be true.
	IsS7 bool `json:"is_s7"`

	// System is the first field returned in the component ID response.
	System string `json:"system,omitempty"`

	// Module is the second field returned in the component ID response.
	Module string `json:"module,omitempty"`

	// PlantId is the third field returned in the component ID response.
	PlantId string `json:"plant_id,omitempty"`

	// Copyright is the fourth field returned in the component ID response.
	Copyright string `json:"copyright,omitempty"`

	// SerialNumber is the fifth field returned in the component ID response.
	SerialNumber string `json:"serial_number,omitempty"`

	// ModuleType is the sixth field returned in the component ID response.
	ModuleType string `json:"module_type,omitempty"`

	// ReservedForOS is the seventh field returned in the component ID response.
	ReservedForOS string `json:"reserved_for_os,omitempty"`

	// MemorySerialNumber is the eighth field returned in the component ID response.
	MemorySerialNumber string `json:"memory_serial_number,omitempty"`

	// CpuProfile is the ninth field returned in the component ID response.
	CpuProfile string `json:"cpu_profile,omitempty"`

	// OemId is the tenth field returned in the component ID response.
	OEMId string `json:"oem_id,omitempty"`

	// Location is the eleventh field returned in the component ID response.
	Location string `json:"location,omitempty"`

	// ModuleId is the first field returned in the module identification response.
	ModuleId string `json:"module_id,omitempty"`

	// Hardware is the second field returned in the module identification response.
	Hardware string `json:"hardware,omitempty"`

	// Fiirmware is the third field returned in the module identification response.
	Firmware string `json:"firmware,omitempty"`
}
