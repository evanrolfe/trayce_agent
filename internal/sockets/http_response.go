package sockets

import (
	"fmt"
	"strings"
)

type HTTPResponse struct {
	Status      int
	StatusMsg   string
	HttpVersion string
	Headers     map[string][]string
	Payload     []byte
}

func (resp *HTTPResponse) AddPayload(data []byte) {
	resp.Payload = append(resp.Payload, data...)
}

func (resp *HTTPResponse) IsGRPC() bool {
	contentTypes, exists := resp.Headers["content-type"]
	if !exists {
		return false
	}

	return strings.Contains(contentTypes[0], "application/grpc")
}

func (resp *HTTPResponse) String() string {
	str := fmt.Sprintf("HTTP/%s %d %s\n", resp.HttpVersion, resp.Status, resp.StatusMsg)

	for key, values := range resp.Headers {
		str += fmt.Sprintf("%s: %s\n", key, strings.Join(values, ";"))
	}

	if len(resp.Payload) > 0 {
		str += "\n"
		str += string(resp.Payload)
	}

	return str
}
