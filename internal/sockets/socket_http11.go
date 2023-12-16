package sockets

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"slices"
	"strconv"
	"strings"

	"github.com/evanrolfe/dockerdog/internal/bpf_events"
)

type SocketHttp11 struct {
	LocalAddr  string
	RemoteAddr string
	Protocol   string
	Pid        uint32
	Fd         uint32
	SSL        bool
	// Stores the bytes being received from DataEvent until they form a full HTTP request or response
	dataBuf []byte
	// If a flow is observed, then these are called
	flowCallbacks []func(Flow)
}

func NewSocketHttp11(event *bpf_events.ConnectEvent) SocketHttp11 {
	socket := SocketHttp11{
		LocalAddr: "unknown",
		Pid:       event.Pid,
		Fd:        event.Fd,
		SSL:       false,
		dataBuf:   []byte{},
	}

	socket.LocalAddr = fmt.Sprintf("%s", event.LocalIPAddr())
	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)

	return socket
}

func (socket *SocketHttp11) Key() string {
	return fmt.Sprintf("%d-%d", socket.Pid, socket.Fd)
}

func (socket *SocketHttp11) Clear() {
	socket.clearDataBuffer()
}

func (socket *SocketHttp11) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

// ProcessConnectEvent is called when the connect event arrives after the data event
func (socket *SocketHttp11) ProcessConnectEvent(event *bpf_events.ConnectEvent) {
	socket.LocalAddr = fmt.Sprintf("%s", event.LocalIPAddr())
	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)
}

func (socket *SocketHttp11) ProcessDataEvent(event *bpf_events.DataEvent) {
	fmt.Println("[SocketHttp1.1] ProcessDataEvent, dataBuf len:", len(socket.dataBuf), " ssl?", event.SSL())
	// if event.SSL() && !socket.SSL {
	// 	fmt.Println("[SocketHttp1.1] clearing dataBuffer")
	// 	socket.clearDataBuffer()
	// 	socket.SSL = true
	// }

	// NOTE: What happens here is that when ssl requests are intercepted twice: first by the uprobe, then by the kprobe
	// this check fixes that because the encrypted data is dropped since it doesnt start with GET
	if string(event.Payload()[0:3]) == "GET" || string(event.Payload()[0:4]) == "HTTP" {
		socket.clearDataBuffer()
		fmt.Println("[SocketHttp1.1] clearing dataBuffer")
	}

	socket.dataBuf = append(socket.dataBuf, stripTrailingZeros(event.Payload())...)

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
		return
	}

	// Events from Go still have carriage returns and chunk-related bytes in their payloads
	// so we need to parse them differently
	// TODO: Do not rely on hard coding these numbers
	isFromGo := (event.DataType == 6 || event.DataType == 7)

	// 2. Attempt to parse buffer as an HTTP response
	resp, decompressedBuf := socket.parseHTTPResponse(socket.dataBuf, isFromGo)
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
	fmt.Printf("[Flow] %s - Local: %s, Remote: %s\n", "", flow.LocalAddr, flow.RemoteAddr)
	flow.Debug()

	for _, callback := range socket.flowCallbacks {
		callback(flow)
	}
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

// TODO: Go's HTTP parsing lib has some weird behaviour and doesn't always work in the way we need it to. We should
// probably just write our own HTTP parsing function, there are so many work-arounds an extra checks I need to do here
// just to be able to use the std lib, its probably more complicated then rolling our own parser..
func (socket *SocketHttp11) parseHTTPResponse(buf []byte, isFromGo bool) (*http.Response, []byte) {
	// Hacky solution because http.ReadResponse does not return the Transfer-Encoding header for some stupid reason
	isChunked := false
	fullHeaders, err := parseHTTPResponseHeaders(buf)
	if err != nil {
		fmt.Println("Error parsing response:", err)
		return nil, []byte{}
	}
	for key, value := range fullHeaders {
		if key == "transfer-encoding" && slices.Contains(value, "chunked") {
			isChunked = true
		}
	}

	// If its chunked but does not have the final chunk, then the response is not complete
	if isFromGo && isChunked && len(buf) >= 5 {
		// If the last chunk is on the trailer chunk: 0\r\n\r\n
		if buf[len(buf)-5] != 0x30 || buf[len(buf)-4] != 0x0d || buf[len(buf)-3] != 0x0a || buf[len(buf)-2] != 0x0d || buf[len(buf)-1] != 0x0a {
			return nil, []byte{}
		}
	}

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
		if err != io.ErrUnexpectedEOF {
			fmt.Println("Error reading response body:", err)
			return nil, []byte{}
		}
	}

	var bufReturn *[]byte

	if resp.Header.Get("Content-Encoding") == "gzip" {
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
			fmt.Println("ERROR", err)
		}

		bufReturn = &buf2
	} else {
		bufReturn = &buf
	}

	// Check we actually have the full body
	contentLengthHdr := resp.Header.Get("Content-Length")
	if contentLengthHdr != "" {
		contentLength, err := strconv.Atoi(contentLengthHdr)
		if err != nil {
			return resp, *bufReturn
		}

		if len(body) < contentLength {
			return nil, []byte{}
		}
	}

	return resp, *bufReturn

}

func (socket *SocketHttp11) clearDataBuffer() {
	socket.dataBuf = []byte{}
}

func stripTrailingZeros(data []byte) []byte {
	// Start from the end of the slice
	for i := len(data) - 1; i >= 0; i-- {
		// If the byte is not 0x00, break the loop
		if data[i] != 0x00 {
			return data[:i+1] // Return the slice up to the non-00 byte
		}
	}

	// If the slice is all 00 bytes, return an empty slice
	return []byte{}
}

// This is necessary because Go's http.ReadResponse seems to leave out the transfer-encoding header which we need
// in order to know if the response is chunked or not. Note - all header keys are downcased.
func parseHTTPResponseHeaders(responseBytes []byte) (map[string][]string, error) {
	headers := make(map[string][]string)

	// Convert the byte slice to a reader
	reader := bufio.NewReader(bytes.NewReader(responseBytes))

	// Read the status line
	_, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("error reading status line: %v", err)
	}

	// Read headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(strings.ToLower(parts[0]))
			value := strings.TrimSpace(parts[1])
			headers[key] = append(headers[key], value)
		}
	}

	return headers, nil

}
