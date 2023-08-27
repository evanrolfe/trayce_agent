package sockets

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/evanrolfe/dockerdog/internal/bpf_events"
)

type SocketHttp11 struct {
	LocalAddr   string
	RemoteAddr  string
	Protocol    string
	Pid         uint32
	Fd          uint32
	dataBuf     []byte
	bufferedReq *http.Request
	msgBuf      *SocketMsg
}

func NewSocketHttp11(Pid uint32, Fd uint32) *SocketHttp11 {
	m := &SocketHttp11{
		Pid:     Pid,
		Fd:      Fd,
		dataBuf: []byte{},
	}
	return m
}

func (socket *SocketHttp11) IsComplete() bool {
	return (socket.LocalAddr == "" || socket.RemoteAddr == "" || socket.Protocol == "")
}

func (socket *SocketHttp11) Key() string {
	return fmt.Sprintf("%d-%d", socket.Pid, socket.Fd)
}

func (socket *SocketHttp11) ProcessDataEvent(event *bpf_events.DataEvent) *SocketMsg {
	socket.dataBuf = append(socket.dataBuf, event.Payload()...)

	// Attempt to parse buffer as an HTTP request
	req := socket.parseHTTPRequest(socket.dataBuf)
	if req != nil {
		if socket.msgBuf != nil {
			fmt.Println("[WARNING] a request was received out-of-order")
			return nil
		}

		socket.msgBuf = NewSocketMsg(socket.dataBuf)
		socket.clearDataBuffer()

		return socket.msgBuf
	}

	if socket.msgBuf == nil {
		fmt.Println("[WARNING] a response was received out-of-order")
		return nil
	}

	// Attempt to parse buffer as an HTTP response
	resp := socket.parseHTTPResponse(socket.dataBuf)
	if resp != nil {
		socket.msgBuf.AddResponse(socket.dataBuf)
		finalMsg := socket.msgBuf.Clone()

		socket.clearDataBuffer()
		socket.clearMsgBuffer()

		return &finalMsg
	}

	return nil
}

func (socket *SocketHttp11) parseHTTPRequest(buf []byte) *http.Request {
	// Try parsing the buffer to an HTTP response
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
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

	return req
}

func (socket *SocketHttp11) parseHTTPResponse(buf []byte) *http.Response {
	// Try parsing the buffer to an HTTP response
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf)), nil)
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

	return resp
}

func (socket *SocketHttp11) clearDataBuffer() {
	socket.dataBuf = []byte{}
}

func (socket *SocketHttp11) clearMsgBuffer() {
	socket.msgBuf = nil
}

func (socket *SocketHttp11) clearReqBuffer() {
	socket.bufferedReq = nil
}
