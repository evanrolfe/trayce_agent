package sockets

import (
	"fmt"
)

type FlowRequest interface {
	AddPayload(data []byte)
	String() string
}

type FlowResponse interface {
	AddPayload(data []byte)
	String() string
}

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

func NewFlowRequest(uuid string, localAddr string, remoteAddr string, l4protocol string, l7protocol string, pid int, fd int, request FlowRequest) *Flow {
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

func NewFlowResponse(uuid string, localAddr string, remoteAddr string, l4protocol string, l7protocol string, pid int, fd int, response FlowResponse) *Flow {
	m := &Flow{
		UUID:       uuid,
		SourceAddr: localAddr,
		DestAddr:   remoteAddr,
		L4Protocol: l4protocol,
		L7Protocol: l7protocol,
		PID:        pid,
		FD:         fd,
		Request:    nil,
		Response:   response,
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
	flow.Response = &HTTPResponse{}
}

// AddPayload adds bytes onto either the request or the response depending on which type the flow is
func (flow *Flow) AddPayload(data []byte) {
	if flow.Request != nil {
		flow.Request.AddPayload(data)
	} else if flow.Response != nil {
		flow.Response.AddPayload(data)
	}
}

func (flow *Flow) Debug() {
	if flow.Request != nil {
		fmt.Println(flow.Request.String())
	}

	if flow.Response != nil {
		fmt.Println(flow.Response.String())
	}
}
