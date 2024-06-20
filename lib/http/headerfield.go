package http

type HeaderField struct {
	Name  string `json:"name,omitempty"`
	Value []byte `json:"value,omitempty"`
}

func (uh HeaderField) Set(key string, value []byte) {
	uh.Name = key
	uh.Value = value
}
