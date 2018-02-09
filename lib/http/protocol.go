package http

type Protocol struct {
	Name  string `json:"name,omitempty"`
	Major int    `json:"major,omitempty"`
	Minor int    `json:"minor,omitempty"`
}
