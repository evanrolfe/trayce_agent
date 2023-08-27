package models

import (
	"fmt"
	"io"
	"net/http"
)

type SocketMsgI interface {
	Debug()
}

type SocketMsg struct {
	request  *http.Request
	response *http.Response
}

func SocketMsgFromRequest(request *http.Request) *SocketMsg {
	m := &SocketMsg{request: request, response: nil}
	return m
}

func SocketMsgFromResponse(response *http.Response) *SocketMsg {
	m := &SocketMsg{request: nil, response: response}
	return m
}

func (msg *SocketMsg) Debug() {
	fmt.Println("------------------------------------------------")
	if msg.request != nil {
		body, err := io.ReadAll(msg.request.Body)
		if err != nil {
			fmt.Println("Error reading request body:", err)
		}
		msg.request.Body.Close()

		fmt.Println("Request:", msg.request.Method, msg.request.URL)
		fmt.Println(string(body))
	}

	if msg.response != nil {
		body, err := io.ReadAll(msg.response.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
		}
		msg.response.Body.Close()

		fmt.Println("Response:", msg.response.Status)
		fmt.Println("Content Length:", msg.response.ContentLength)
		fmt.Println("Transfer Encoding:", msg.response.TransferEncoding)
		fmt.Println(string(body))
	}
}
