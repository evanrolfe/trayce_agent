package sockets

import (
	"fmt"
)

// -------------------------------------------------------------------------------------------------
// FlowRequest
// -------------------------------------------------------------------------------------------------
type FlowRequest interface {
	AddPayload(data []byte)
}

// HTTPRequest
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

// TODO: Rename to AddPayload()
func (req *HTTPRequest) AddPayload(data []byte) {
	req.Payload = append(req.Payload, data...)
}

// TODO: GRPCRequest
type GRPCRequest struct {
	data []byte
}

func (req *GRPCRequest) AddPayload(data []byte) {
	req.data = append(req.data, data...)
}

func (req *GRPCRequest) GetData() []byte {
	return req.data
}

// -------------------------------------------------------------------------------------------------
// FlowResponse
// -------------------------------------------------------------------------------------------------
type FlowResponse interface {
	AddData(data []byte)
	GetData() []byte
}

// HTTPResponse
type HTTPResponse struct {
	data []byte
}

func (res *HTTPResponse) AddData(data []byte) {
	res.data = append(res.data, data...)
}

func (res *HTTPResponse) GetData() []byte {
	return res.data
}

// TODO: GRPCRequest
type GRPCResponse struct {
}

func (req *GRPCResponse) AddData(data []byte) {
}

// -------------------------------------------------------------------------------------------------
// Flow
// -------------------------------------------------------------------------------------------------
// Flow represents an exchange of data over a socket in the form of request + response.
type Flow struct {
	UUID       string
	SourceAddr string
	DestAddr   string
	L4Protocol string
	L7Protocol string
	Request    FlowRequest
	Response   FlowResponse
	PID        int
	FD         int
}

func NewFlowRequest(uuid string, localAddr string, remoteAddr string, l4protocol string, l7protocol string, pid int, fd int, request *HTTPRequest) *Flow {
	m := &Flow{
		UUID:       uuid,
		SourceAddr: localAddr,
		DestAddr:   remoteAddr,
		L4Protocol: l4protocol,
		L7Protocol: l7protocol,
		PID:        pid,
		FD:         fd,
		Request:    request,
		Response:   nil,
	}
	return m
}

func NewFlowResponse(uuid string, localAddr string, remoteAddr string, l4protocol string, l7protocol string, pid int, fd int, response []byte) *Flow {
	m := &Flow{
		UUID:       uuid,
		SourceAddr: localAddr,
		DestAddr:   remoteAddr,
		L4Protocol: l4protocol,
		L7Protocol: l7protocol,
		PID:        pid,
		FD:         fd,
		Response:   &HTTPResponse{data: response},
	}
	return m
}

func (flow *Flow) Clone() Flow {
	m := Flow{
		UUID:       flow.UUID,
		SourceAddr: flow.SourceAddr,
		DestAddr:   flow.DestAddr,
		L4Protocol: flow.L4Protocol,
		L7Protocol: flow.L7Protocol,
		PID:        flow.PID,
		FD:         flow.FD,
		Request:    flow.Request,
		Response:   flow.Response,
	}
	return m
}

func (flow *Flow) Complete() bool {
	return flow.L4Protocol != "" && flow.L7Protocol != "" && flow.DestAddr != ""
}

func (flow *Flow) AddResponse(response []byte) {
	flow.Response = &HTTPResponse{data: response}
}

// AddData adds bytes onto either the request or the response depending on which type the flow is
func (flow *Flow) AddData(data []byte) {
	if flow.Request != nil {
		flow.Request.AddPayload(data)
	} else if flow.Response != nil {
		flow.Response.AddData(data)
	}
}

func (flow *Flow) Debug() {
	if flow.Request != nil {
		fmt.Println("Request:")
		// TODO: print the debug info
	}

	if flow.Response != nil {
		fmt.Println("Response:")

		if len(flow.Response.GetData()) >= 512 {
			fmt.Println(string(flow.Response.GetData()[0:512]))
		} else {
			fmt.Println(string(flow.Response.GetData()))
		}
	}
}
