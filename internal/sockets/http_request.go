package sockets

import (
	"fmt"
	"strings"
)

type HTTPRequest struct {
	Method      string
	Host        string
	Path        string
	HttpVersion string
	Headers     map[string][]string
	Payload     []byte
}

func NewHTTPRequest(method, path, host, httpVersion string, payload []byte, headers map[string][]string) HTTPRequest {
	return HTTPRequest{
		Method:      method,
		Path:        path,
		Host:        host,
		HttpVersion: httpVersion,
		Payload:     payload,
		Headers:     headers,
	}
}

func (req *HTTPRequest) AddPayload(data []byte) {
	req.Payload = append(req.Payload, data...)
}

func (req *HTTPRequest) IsGRPC() bool {
	contentTypes, exists := req.Headers["content-type"]
	if !exists {
		return false
	}

	return strings.Contains(contentTypes[0], "application/grpc")
}

func (req *HTTPRequest) String() string {
	str := fmt.Sprintf("%s %s HTTP/%s\n", req.Method, req.Path, req.HttpVersion)

	for key, values := range req.Headers {
		str += fmt.Sprintf("%s: %s\n", key, strings.Join(values, ";"))
	}

	if len(req.Payload) > 0 {
		str += "\n"
		str += string(req.Payload)
	}

	return str
}
