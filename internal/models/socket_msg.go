package models

import (
	"encoding/hex"
	"fmt"
	"net/http"
)

type SocketMsgI interface {
	Debug()
	AddResponse(response *http.Response)
}

// TODO: Rename this to SocketFLow
type SocketMsg struct {
	request  []byte
	response []byte
}

func NewSocketMsg(request []byte) *SocketMsg {
	m := &SocketMsg{request: request, response: nil}
	return m
}

func (msg *SocketMsg) Clone() SocketMsg {
	m := SocketMsg{request: msg.request, response: msg.response}
	return m
}

func (msg *SocketMsg) AddResponse(response []byte) {
	msg.response = response
}

func (msg *SocketMsg) Debug() {
	fmt.Println("------------------------------------------------")
	fmt.Printf("Request:\n%s\n", string(msg.request))

	if msg.response != nil {
		// fmt.Printf("Response:\n%s\n", string(msg.response))
		fmt.Println("Response:")
		fmt.Print(hex.Dump(msg.response))
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
