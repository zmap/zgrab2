package dnp3

type DNP3Log struct {
	IsDNP3      bool   `json:"is_dnp3"`
	RawResponse []byte `json:"raw_response,omitempty"`
}
