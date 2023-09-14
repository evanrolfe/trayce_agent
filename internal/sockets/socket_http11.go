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
	LocalAddr   string
	RemoteAddr  string
	Protocol    string
	Pid         uint32
	Fd          uint32
	dataBuf     []byte
	bufferedReq *http.Request
	msgBuf      *Flow
}

func NewSocketHttp11(event *bpf_events.ConnectEvent) SocketHttp11 {
	socket := SocketHttp11{
		LocalAddr: "unknown",
		Pid:       event.Pid,
		Fd:        event.Fd,
		dataBuf:   []byte{},
	}

	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)

	return socket
}

func (socket *SocketHttp11) ProcessDataEvent(event *bpf_events.DataEvent) *Flow {
	socket.dataBuf = append(socket.dataBuf, event.Payload()...)

	// Attempt to parse buffer as an HTTP request
	req := socket.parseHTTPRequest(socket.dataBuf)
	if req != nil {
		if socket.msgBuf != nil {
			fmt.Println("[WARNING] a request was received out-of-order")
			return nil
		}

		socket.msgBuf = NewFlow(
			socket.LocalAddr,
			socket.RemoteAddr,
			"tcp", // TODO Use constants here instead
			"http",
			socket.dataBuf,
		)
		socket.clearDataBuffer()

		return socket.msgBuf
	}

	if socket.msgBuf == nil {
		fmt.Printf("[WARNING] a response was received out-of-order, conn_id: %d-%d len: %d\n", socket.Pid, socket.Fd, len(event.Payload()))
		fmt.Println(hex.Dump(event.Payload()))
		return nil
	}

	// Attempt to parse buffer as an HTTP response
	resp, decompressedBuf := socket.parseHTTPResponse(socket.dataBuf)
	if resp != nil {
		socket.msgBuf.AddResponse(decompressedBuf)
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

func (socket *SocketHttp11) clearMsgBuffer() {
	socket.msgBuf = nil
}
