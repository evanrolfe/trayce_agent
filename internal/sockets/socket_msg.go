package sockets

import (
	"fmt"
	"net/http"
)

type SocketMsgI interface {
	Debug()
	AddResponse(response *http.Response)
}

// TODO: Rename this to SocketFLow
type SocketMsg struct {
	LocalAddr  string
	RemoteAddr string
	L4Protocol string
	L7Protocol string
	Request    []byte
	Response   []byte
}

// TODO: This should probably accept a SocketI instead of primitive args
func NewSocketMsg(
	localAddr string,
	remoteAddr string,
	l4protocol string,
	l7protocol string,
	request []byte) *SocketMsg {
	m := &SocketMsg{
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		L4Protocol: l4protocol,
		L7Protocol: l7protocol,
		Request:    request,
		Response:   nil,
	}
	return m
}

func (msg *SocketMsg) Clone() SocketMsg {
	m := SocketMsg{
		LocalAddr:  msg.LocalAddr,
		RemoteAddr: msg.RemoteAddr,
		L4Protocol: msg.L4Protocol,
		L7Protocol: msg.L7Protocol,
		Request:    msg.Request,
		Response:   msg.Response,
	}
	return m
}

func (msg *SocketMsg) AddResponse(response []byte) {
	msg.Response = response
}

func (msg *SocketMsg) Debug() {
	fmt.Println("------------------------------------------------")
	fmt.Printf("Request:\n%s\n", string(msg.Request))

	if msg.Response != nil {
		fmt.Println("Response:")

		if len(msg.Response) >= 256 {
			fmt.Println(string(msg.Response[0:256]))
		} else {
			fmt.Println(string(msg.Response))
		}

		// fmt.Print(hex.Dump(msg.response))
	}

	// if msg.request != nil {
	// 	body, err := io.ReadAll(msg.request.Body)
	// 	if err != nil {
	// 		fmt.Println("Error reading request body:", err)
	// 	}
	// 	msg.request.Body.Close()

	// 	fmt.Println("Request:", msg.request.Method, msg.request.URL)
	// 	fmt.Println(string(body))
	// }

	// if msg.response != nil {
	// 	body, err := io.ReadAll(msg.response.Body)
	// 	if err != nil {
	// 		fmt.Println("Error reading response body:", err)
	// 	}
	// 	msg.response.Body.Close()

	// 	fmt.Println("Response:", msg.response.Status)
	// 	fmt.Println("Content Length:", msg.response.ContentLength)
	// 	fmt.Println("Transfer Encoding:", msg.response.TransferEncoding)
	// 	fmt.Println(string(body))
	// }
}
