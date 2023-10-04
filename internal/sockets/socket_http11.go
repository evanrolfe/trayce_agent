package sockets

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/evanrolfe/dockerdog/internal/bpf_events"
)

type SocketHttp11 struct {
	LocalAddr  string
	RemoteAddr string
	Protocol   string
	Pid        uint32
	Fd         uint32
	// Stores the bytes being received from DataEvent until they form a full HTTP request or response
	dataBuf []byte
	// Store incomplete flows (no RemoteAddr set) which are buffered until we receive a ConnectEvent
	bufferedFlows []Flow
	// If a flow is observed, then these are called
	flowCallbacks []func(Flow)
}

func NewSocketHttp11(event *bpf_events.ConnectEvent) SocketHttp11 {
	socket := SocketHttp11{
		LocalAddr:     "unknown",
		Pid:           event.Pid,
		Fd:            event.Fd,
		dataBuf:       []byte{},
		bufferedFlows: []Flow{},
	}

	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)

	return socket
}

// TODO: Make NewSocketHttp11 accept an IEvent interface and then decide how to make the socket based on its type
func NewSocketHttp11FromData(event *bpf_events.DataEvent) SocketHttp11 {
	socket := SocketHttp11{
		LocalAddr:     "unknown",
		Pid:           event.Pid,
		Fd:            event.Fd,
		dataBuf:       []byte{},
		bufferedFlows: []Flow{},
	}

	return socket
}

func (socket *SocketHttp11) Key() string {
	return fmt.Sprintf("%d-%d", socket.Pid, socket.Fd)
}

func (socket *SocketHttp11) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

// ProcessConnectEvent is called when the connect event arrives after the data event
func (socket *SocketHttp11) ProcessConnectEvent(event *bpf_events.ConnectEvent) {
	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)

	// Connect events came come after DataEvents, so we buffer those flows until we receive a ConnectEvent which sets
	// socket.RemoteAddr. TODO - would probably be simpler if we buffered the events first then processed them in desired order
	socket.releaseBufferedFlows()
}

func (socket *SocketHttp11) ProcessDataEvent(event *bpf_events.DataEvent) {
	fmt.Println("[SocketHttp1.1] ProcessDataEvent, dataBuf len:", len(socket.dataBuf))

	if socket.RemoteAddr == "127.0.0.1:4123" {
		fmt.Println(hex.Dump(event.Payload()))
	}

	// NOTE: What happens here is that when ssl requests are intercepted twice: first by the uprobe, then by the kprobe
	// this check fixes that because the encrypted data is dropped since it doesnt start with GET
	// if string(event.Payload()[0:3]) == "GET" {
	// 	socket.clearDataBuffer()
	// 	fmt.Println("[SocketHttp1.1] clearing dataBuffer")
	// }

	socket.dataBuf = append(socket.dataBuf, event.Payload()...)

	// 1. Attempt to parse buffer as an HTTP request
	req := socket.parseHTTPRequest(socket.dataBuf)
	if req != nil {
		fmt.Println("[SocketHttp1.1] HTTP request complete")
		flow := NewFlow(
			socket.LocalAddr,
			socket.RemoteAddr,
			"tcp", // TODO Use constants here instead
			"http",
			int(socket.Pid),
			int(socket.Fd),
			socket.dataBuf,
		)
		socket.clearDataBuffer()
		socket.sendFlowBack(*flow)
	}

	// 2. Attempt to parse buffer as an HTTP response
	resp, decompressedBuf := socket.parseHTTPResponse(socket.dataBuf)
	if resp != nil {
		fmt.Println("[SocketHttp1.1] HTTP response complete")

		flow := NewFlowResponse(
			socket.LocalAddr,
			socket.RemoteAddr,
			"tcp", // TODO Use constants here instead
			"http",
			int(socket.Pid),
			int(socket.Fd),
			socket.dataBuf,
		)

		flow.AddResponse(decompressedBuf)

		socket.clearDataBuffer()
		socket.sendFlowBack(*flow)
	}
}

func (socket *SocketHttp11) sendFlowBack(flow Flow) {
	if !flow.Complete() {
		socket.bufferedFlows = append(socket.bufferedFlows, flow)
		return
	}

	for _, callback := range socket.flowCallbacks {
		callback(flow)
	}
}

func (socket *SocketHttp11) releaseBufferedFlows() {
	if len(socket.bufferedFlows) == 0 {
		return
	}

	for _, flow := range socket.bufferedFlows {
		flow.RemoteAddr = socket.RemoteAddr

		socket.sendFlowBack(flow)
	}

	socket.bufferedFlows = []Flow{}
}

func (socket *SocketHttp11) parseHTTPRequest(buf []byte) *http.Request {
	// Try parsing the buffer to an HTTP response
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
	if err != nil {
		// fmt.Println("Error parsing response:", err)
		return nil
	}

	// Readall from the body to ensure its complete
	_, err = io.ReadAll(req.Body)
	if err != nil {
		// fmt.Println("Error reading response body:", err)
		return nil
	}
	req.Body.Close()

	return req
}

func (socket *SocketHttp11) parseHTTPResponse(buf []byte) (*http.Response, []byte) {
	// Try parsing the buffer to an HTTP response
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf)), nil)
	if err != nil {
		// fmt.Println("Error parsing response:", err)
		return nil, []byte{}
	}

	// Readall from the body to ensure its complete
	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		// fmt.Println("Error reading response body:", err)
		return nil, []byte{}
	}

	if resp.Header.Get("Content-Encoding") != "gzip" {
		return resp, buf
	}

	// Decompress if the body is gzip compressed
	gzipReader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		fmt.Println("ERROR", err)
	}
	defer gzipReader.Close()

	decompressedBody, err := io.ReadAll(gzipReader)
	if err != nil {
		fmt.Println("ERROR", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(decompressedBody))
	defer resp.Body.Close()

	buf2, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatalln(err)
	}

	return resp, buf2

}

func (socket *SocketHttp11) clearDataBuffer() {
	socket.dataBuf = []byte{}
}
