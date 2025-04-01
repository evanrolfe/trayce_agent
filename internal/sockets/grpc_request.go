package sockets

type GRPCRequest struct {
	Path    string
	Headers map[string][]string
	Payload []byte
}

func (req *GRPCRequest) AddPayload(data []byte) {
	req.Payload = append(req.Payload, data...)
}

func (req *GRPCRequest) String() string {
	return ""
}
