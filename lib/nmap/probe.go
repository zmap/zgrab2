package nmap

import "github.com/zmap/zgrab2/lib/nmap/template"

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

type Template = template.Template

type Match struct {
	Service string
	MatchPattern
	Info[Template]
	Soft bool
}

type MatchPattern struct {
	Regex string
	Flags string
}

type Info[T any] struct {
	VendorProductName T
	Version           T
	Info              T
	Hostname          T
	OS                T
	DeviceType        T
	CPE               []T
}
