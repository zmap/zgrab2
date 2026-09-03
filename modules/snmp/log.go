package snmp

type Log struct {
	IsSNMP            bool              `json:"is_snmp"`
	Version           string            `json:"version,omitempty"`
	Probe             string            `json:"probe,omitempty"`
	Role              string            `json:"role,omitempty"`
	Community         string            `json:"community,omitempty"`
	Port              uint              `json:"port,omitempty"`
	RequestID         int               `json:"request_id,omitempty"`
	ErrorStatus       int               `json:"error_status"`
	ErrorIndex        int               `json:"error_index"`
	RawResponseLength int               `json:"raw_response_length"`
	Values            map[string]string `json:"values,omitempty"`

	EngineID        string `json:"engine_id,omitempty"`
	EngineIDFormat  string `json:"engine_id_format,omitempty"`
	EngineIDData    string `json:"engine_id_data,omitempty"`
	EnterpriseID   uint32 `json:"enterprise_id,omitempty"`
	EnterpriseName string `json:"enterprise_name,omitempty"`
	SNMPEngineBoots int    `json:"snmp_engine_boots,omitempty"`
	SNMPEngineTime  int    `json:"snmp_engine_time,omitempty"`
	ReportOID       string `json:"report_oid,omitempty"`
	ReportValue     string `json:"report_value,omitempty"`
	SysDescr    string `json:"sys_descr,omitempty"`
	SysObjectID string `json:"sys_object_id,omitempty"`
	SysUpTime   string `json:"sys_uptime,omitempty"`
	SysContact  string `json:"sys_contact,omitempty"`
	SysName     string `json:"sys_name,omitempty"`
	SysLocation string `json:"sys_location,omitempty"`
	SysServices int    `json:"sys_services,omitempty"`
}
