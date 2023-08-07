package nmap

type ServiceProbe struct {
	Name        string
	Protocol    Protocol
	ProbeString string
	NoPayload   bool
	Matches     []Match
}

type Protocol string

const (
	UnknownProtocol = Protocol("UnknownProtocol")
	TCP             = Protocol("TCP")
	UDP             = Protocol("UDP")
)

type Match struct {
	Service string
	MatchPattern
	VersionInfo
	Soft bool
}

type MatchPattern struct {
	Regex string
	Flags string
}

type VersionInfo struct {
	VendorProductName string
	Version           string
	Info              string
	Hostname          string
	OS                string
	DeviceType        string
	CPE               []string
}
