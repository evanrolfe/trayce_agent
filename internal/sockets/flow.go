package sockets

import (
	"fmt"
)

// Flow represents an exchange of data over a socket in the form of request + response.
type Flow struct {
	UUID       string
	LocalAddr  string
	RemoteAddr string
	L4Protocol string
	L7Protocol string
	Request    []byte
	Response   []byte
	Pid        int
	Fd         int
}

func NewFlow(uuid string, localAddr string, remoteAddr string, l4protocol string, l7protocol string, pid int, fd int, request []byte) *Flow {
	m := &Flow{
		UUID:       uuid,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		L4Protocol: l4protocol,
		L7Protocol: l7protocol,
		Pid:        pid,
		Fd:         fd,
		Request:    request,
		Response:   nil,
	}
	return m
}

func NewFlowResponse(uuid string, localAddr string, remoteAddr string, l4protocol string, l7protocol string, pid int, fd int, response []byte) *Flow {
	m := &Flow{
		UUID:       uuid,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		L4Protocol: l4protocol,
		L7Protocol: l7protocol,
		Pid:        pid,
		Fd:         fd,
		Response:   response,
	}
	return m
}

func (flow *Flow) Clone() Flow {
	m := Flow{
		UUID:       flow.UUID,
		LocalAddr:  flow.LocalAddr,
		RemoteAddr: flow.RemoteAddr,
		L4Protocol: flow.L4Protocol,
		L7Protocol: flow.L7Protocol,
		Pid:        flow.Pid,
		Fd:         flow.Fd,
		Request:    flow.Request,
		Response:   flow.Response,
	}
	return m
}

func (flow *Flow) Complete() bool {
	return flow.L4Protocol != "" && flow.L7Protocol != "" && flow.RemoteAddr != ""
}

func (flow *Flow) AddResponse(response []byte) {
	flow.Response = response
}

// AddData adds bytes onto either the request or the response depending on which type the flow is
func (flow *Flow) AddData(data []byte) {
	if len(flow.Request) > 0 {
		flow.Request = append(flow.Request, data...)
	} else if len(flow.Response) > 0 {
		flow.Response = append(flow.Response, data...)
	}
}

func (flow *Flow) Debug() {
	if flow.Request != nil {
		fmt.Println("Request:")
		fmt.Println(string(flow.Request))
	}

	if flow.Response != nil {
		fmt.Println("Response:")

		if len(flow.Response) >= 512 {
			fmt.Println(string(flow.Response[0:512]))
		} else {
			fmt.Println(string(flow.Response))
		}

		// fmt.Print(hex.Dump(flow.response))
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
