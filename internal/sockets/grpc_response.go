package sockets

type GRPCResponse struct {
	Headers map[string][]string
	Payload []byte
}

func (resp *GRPCResponse) AddPayload(data []byte) {
	resp.Payload = append(resp.Payload, data...)
}

func (resp *GRPCResponse) String() string {
	return ""
}
