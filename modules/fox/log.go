package fox

import (
	"github.com/zmap/zgrab2"
)

// FoxLog is the struct returned to the caller.
type FoxLog struct {
	// IsFox should always be true (otherwise, the result should have been nil).
	IsFox bool `json:"is_fox"`

	// Version corresponds to the "fox.version" response field.
	Version string `json:"version"`

	// Id corresponds to the "id" response field, which is decoded as a decimal integer.
	Id uint32 `json:"id"`

	// Hostname corresponds to the "hostName" field.
	Hostname string `json:"hostname,omitempty"`

	// HostAddress corresponds to the "hostAddress" field.
	HostAddress string `json:"host_address,omitempty"`

	// AppName corresponds to the "app.name" field.
	AppName string `json:"app_name,omitempty"`

	// AppVersion corresponds to the "app.version" field.
	AppVersion string `json:"app_version,omitempty"`

	// VMName corresponds to the "vm.name" field.
	VMName string `json:"vm_name,omitempty"`

	// VMVersion corresponds to the "vm.version" field.
	VMVersion string `json:"vm_version,omitempty"`

	// OSName corresponds to the "os.name" field.
	OSName string `json:"os_name,omitempty"`

	// OSVersion corresponds to the "os.version" field.
	OSVersion string `json:"os_version,omitempty"`

	// StationName corresponds to the "station.name" field.
	StationName string `json:"station_name,omitempty"`

	// Language corresponds to the "lang" field.
	Language string `json:"language,omitempty"`

	// TimeZone corresponds to the "timeZone" field (or, that portion of it before the first semicolon).
	TimeZone string `json:"time_zone,omitempty"`

	// HostId corresponds to the "hostId" field.
	HostId string `json:"host_id,omitempty"`

	// VMUuid corresponds to the "vmUuid" field.
	VMUuid string `json:"vm_uuid,omitempty"`

	// BrandId corresponds to the "brandId" field.
	BrandId string `json:"brand_id,omitempty"`

	// SysInfo corresponds to the "sysInfo" field.
	SysInfo string `json:"sys_info,omitempty"`

	// AuthAgentType corresponds to the "authAgentTypeSpecs" field.
	AuthAgentType string `json:"auth_agent_type,omitempty"`

	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}
