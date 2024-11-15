package sockets

import (
	"fmt"
)

// -------------------------------------------------------------------------------------------------
// FlowRequest
// -------------------------------------------------------------------------------------------------
type FlowRequest interface {
	AddData(data []byte)
	GetData() []byte
}

type HTTPRequest struct {
	Data []byte
}

func (req *HTTPRequest) AddData(data []byte) {
	req.Data = append(req.Data, data...)
}

func (req *HTTPRequest) GetData() []byte {
	return req.Data
}

// -------------------------------------------------------------------------------------------------
// FlowResponse
// -------------------------------------------------------------------------------------------------
type FlowResponse interface {
	AddData(data []byte)
	GetData() []byte
}

type HTTPResponse struct {
	Data []byte
}

func (res *HTTPResponse) AddData(data []byte) {
	res.Data = append(res.Data, data...)
}

func (res *HTTPResponse) GetData() []byte {
	return res.Data
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

func NewFlow(uuid string, localAddr string, remoteAddr string, l4protocol string, l7protocol string, pid int, fd int, request []byte) *Flow {
	m := &Flow{
		UUID:       uuid,
		SourceAddr: localAddr,
		DestAddr:   remoteAddr,
		L4Protocol: l4protocol,
		L7Protocol: l7protocol,
		PID:        pid,
		FD:         fd,
		Request:    &HTTPRequest{Data: request},
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
		Response:   &HTTPResponse{Data: response},
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
	flow.Response = &HTTPResponse{Data: response}
}

// AddData adds bytes onto either the request or the response depending on which type the flow is
func (flow *Flow) AddData(data []byte) {
	if flow.Request != nil {
		flow.Request.AddData(data)
	} else if flow.Response != nil {
		flow.Response.AddData(data)
	}
}

func (flow *Flow) Debug() {
	if flow.Request != nil {
		fmt.Println("Request:")
		// fmt.Println(string(flow.Request.Data))
	}

	if flow.Response != nil {
		fmt.Println("############# Response:")
		// fmt.Println(hex.Dump(flow.Response))

		// if len(flow.Response) >= 512 {
		// 	fmt.Println(string(flow.Response[0:512]))
		// } else {
		// 	fmt.Println(string(flow.Response))
		// }

	}

	// if flow.request != nil {
	// 	body, err := io.ReadAll(flow.request.Body)
	// 	if err != nil {
	// 		fmt.Println("Error reading request body:", err)
	// 	}
	// 	flow.request.Body.Close()

	// 	fmt.Println("Request:", flow.request.Method, flow.request.URL)
	// 	fmt.Println(string(body))
	// }

	// if flow.response != nil {
	// 	body, err := io.ReadAll(flow.response.Body)
	// 	if err != nil {
	// 		fmt.Println("Error reading response body:", err)
	// 	}
	// 	flow.response.Body.Close()

	// 	fmt.Println("Response:", flow.response.Status)
	// 	fmt.Println("Content Length:", flow.response.ContentLength)
	// 	fmt.Println("Transfer Encoding:", flow.response.TransferEncoding)
	// 	fmt.Println(string(body))
	// }
}
