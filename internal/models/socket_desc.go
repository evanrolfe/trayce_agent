package models

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
)

type SocketDesc struct {
	LocalAddr  string
	RemoteAddr string
	Protocol   string
	Pid        uint32
	Fd         uint32
	egressBuf  []byte
	ingressBuf []byte
}

func NewSocketDesc(Pid uint32, Fd uint32) *SocketDesc {
	m := &SocketDesc{
		Pid:        Pid,
		Fd:         Fd,
		egressBuf:  []byte{},
		ingressBuf: []byte{},
	}
	return m
}

func (socket *SocketDesc) IsComplete() bool {
	return (socket.LocalAddr == "" || socket.RemoteAddr == "" || socket.Protocol == "")
}

func (socket *SocketDesc) Key() string {
	return fmt.Sprintf("%d-%d", socket.Pid, socket.Fd)
}

func (socket *SocketDesc) ProcessDataEvent(event *DataEvent) SocketMsgI {
	var buf *[]byte
	if event.Type() == TypeEgress {
		buf = &socket.egressBuf
	} else if event.Type() == TypeIngress {
		buf = &socket.ingressBuf
	} else {
		panic("DataEvent type invalid")
	}

	*buf = append(*buf, event.Payload()...)

	if event.Type() == TypeEgress {
		return socket.processEgressBuf()
	} else {
		return socket.processIngressBuf()
	}
}

func (socket *SocketDesc) processEgressBuf() SocketMsgI {
	// Try parsing the buffer to an HTTP response
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(socket.egressBuf)))
	if err != nil {
		// fmt.Println("Error parsing response:", err)
		return nil
	}

	// Readall from the body to ensure its complete
	body, err := io.ReadAll(req.Body)
	if err != nil {
		// fmt.Println("Error reading response body:", err)
		return nil
	}
	req.Body.Close()

	// Re-add the body so it can be read again later
	req.Body = io.NopCloser(bytes.NewReader(body))

	// Clear the buffer
	socket.egressBuf = []byte{}

	return SocketMsgFromRequest(req)
}

func (socket *SocketDesc) processIngressBuf() SocketMsgI {
	// Try parsing the buffer to an HTTP response
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(socket.ingressBuf)), nil)
	if err != nil {
		// fmt.Println("Error parsing response:", err)
		return nil
	}

	// Readall from the body to ensure its complete
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// fmt.Println("Error reading response body:", err)
		return nil
	}
	resp.Body.Close()

	// Re-add the body so it can be read again later
	resp.Body = io.NopCloser(bytes.NewReader(body))

	// Clear the buffer
	socket.ingressBuf = []byte{}

	return SocketMsgFromResponse(resp)
}
