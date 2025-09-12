package sockets

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/google/uuid"
)

type SocketHttp11 struct {
	Common SocketCommon

	// Stores the bytes being received from DataEvent until they form a full HTTP request or response
	dataBuf []byte
	// When a request is observed, this value is set, when the response comes, we send this value back with the response
	requestUuid string
}

func NewSocketHttp11(sourceAddr, destAddr string, pid, tid, fd uint32) SocketHttp11 {
	socket := SocketHttp11{
		Common: SocketCommon{
			SourceAddr: sourceAddr,
			DestAddr:   destAddr,
			PID:        pid,
			TID:        tid,
			FD:         fd,
			SSL:        false,
		},
		dataBuf:     []byte{},
		requestUuid: "",
	}

	return socket
}

func NewSocketHttp11FromUnknown(unkownSocket *SocketUnknown) SocketHttp11 {
	socket := SocketHttp11{
		Common: SocketCommon{
			SourceAddr: unkownSocket.SourceAddr,
			DestAddr:   unkownSocket.DestAddr,
			PID:        unkownSocket.PID,
			TID:        unkownSocket.TID,
			FD:         unkownSocket.FD,
			SSL:        false,
		},
		dataBuf:     []byte{},
		requestUuid: "",
	}

	return socket
}

func (sk *SocketHttp11) Key() string {
	return sk.Common.Key()
}

func (sk *SocketHttp11) AddFlowCallback(callback func(Flow)) {
	sk.Common.AddFlowCallback(callback)
}

func (sk *SocketHttp11) ProcessDataEvent(event *events.DataEvent) {
	fmt.Println("[SocketHttp1.1] ProcessDataEvent, dataBuf len:", len(sk.dataBuf), " ssl?", event.SSL())
	// fmt.Println(hex.Dump(event.Payload()))

	if sk.Common.SSL && !event.SSL() {
		// If the socket is SSL, then ignore non-SSL events becuase they will just be encrypted gibberish
		return
	}

	if event.SSL() && !sk.Common.SSL {
		fmt.Println("[SocketHttp1.1] upgrading to SSL")
		sk.Common.UpgradeToSSL()
	}

	// NOTE: What happens here is that when ssl requests are intercepted twice: first by the uprobe, then by the kprobe
	// this check fixes that because the encrypted data is dropped since it doesnt start with GET
	if isStartOfHTTPMessage(event.Payload()) {
		sk.clearDataBuffer()
		fmt.Println("[SocketHttp1.1] clearing dataBuffer")
	}

	sk.dataBuf = append(sk.dataBuf, stripTrailingZeros(event.Payload())...)

	// 1. Attempt to parse buffer as an HTTP request
	req := sk.parseHTTPRequest(sk.dataBuf)
	if req != nil {
		sk.requestUuid = uuid.NewString()
		fmt.Println("[SocketHttp1.1] HTTP request complete")
		flow := NewFlowRequest(
			sk.requestUuid,
			sk.Common.SourceAddr,
			sk.Common.DestAddr,
			"tcp", // TODO Use constants here instead
			"http",
			int(sk.Common.PID),
			int(sk.Common.FD),
			convertToHTTPRequest(req),
		)
		sk.clearDataBuffer()
		sk.Common.sendFlowBack(*flow)
		return
	}

	// 2. Attempt to parse buffer as an HTTP response
	// TODO: This code is quite convaluted and could probably be simplified, i.e. by just returning a response struct
	// with the decompressed body set on it
	resp, respBody := sk.parseHTTPResponse(sk.dataBuf)

	if resp != nil {
		fmt.Println("[SocketHttp1.1] HTTP response complete")
		flow := NewFlowResponse(
			sk.requestUuid,
			sk.Common.SourceAddr,
			sk.Common.DestAddr,
			"tcp", // TODO Use constants here instead
			"http",
			int(sk.Common.PID),
			int(sk.Common.FD),
			convertToHTTPResponse(resp, respBody),
		)

		sk.clearDataBuffer()
		sk.Common.sendFlowBack(*flow)
	}
}

func (sk *SocketHttp11) parseHTTPRequest(buf []byte) *http.Request {
	// Try parsing the buffer to an HTTP request
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
	if err != nil {
		// fmt.Println("Error parsing response:", err)
		return nil
	}

	// Read the body to ensure it's complete
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}
	req.Body.Close()

	// Set the body back on the request so it can be read again later
	req.Body = io.NopCloser(bytes.NewReader(body))

	return req
}

// TODO: Go's HTTP parsing lib has some weird behaviour and doesn't always work in the way we need it to. We should
// probably just write our own HTTP parsing function, there are so many work-arounds an extra checks I need to do here
// just to be able to use the std lib, its probably more complicated then rolling our own parser..
func (sk *SocketHttp11) parseHTTPResponse(buf []byte) (*http.Response, []byte) {
	// Using our own header parser code because http.ReadResponse does not return the Transfer-Encoding header for some stupid reason
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
	if isChunked && len(buf) >= 5 {
		trailerChunk := []byte{0x30, 0x0d, 0x0a, 0x0d, 0x0a}
		lastFive := buf[len(buf)-5:]
		// If the last chunk is on the trailer chunk: 0\r\n\r\n
		if !bytes.Equal(lastFive, trailerChunk) {
			fmt.Printf("[SocketHttp1.1] not the last chunk %x\n", lastFive)
			return nil, []byte{}
		}
	}

	// Try parsing the buffer to an HTTP response
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf)), nil)
	if err != nil {
		return nil, []byte{}
	}

	// Readall from the body to ensure its complete
	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		if err != io.ErrUnexpectedEOF {
			fmt.Println("Error reading response body 0:", err)
			return nil, []byte{}
		}
	}

	var bufReturn *[]byte

	if resp.Header.Get("Content-Encoding") == "gzip" {
		decodedBuf, err := decodeGzipResponse(buf)
		if err != nil {
			fmt.Println("ERROR decodeGzipResponse():", err)
			decodedBuf = buf
		} else {
			resp.Header.Del("Content-Length")
		}

		bufReturn = &decodedBuf
	} else {
		bufReturn = &body
	}

	// Check we actually have the full body
	contentLengthHdr := resp.Header.Get("Content-Length")
	if contentLengthHdr != "" {
		contentLength, err := strconv.Atoi(contentLengthHdr)
		if err != nil {
			return resp, *bufReturn
		}

		if len(body) < contentLength {
			return nil, *bufReturn
		}
	}

	return resp, *bufReturn
}

func decodeGzipResponse(buf []byte) ([]byte, error) {
	parts := bytes.SplitN(buf, []byte("\r\n\r\n"), 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid HTTP response: no body found")
	}

	// The body is the part after the double CRLF
	body := parts[1]

	// Create a new gzip reader
	gzReader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gzip.NewReader(): %v", err)
	}
	defer gzReader.Close()

	// Read the decompressed data
	decodedBody, err := io.ReadAll(gzReader)
	if err != nil {
		// return nil, fmt.Errorf("io.ReadAll(): %v", err)
	}

	newBuf := bytes.Join([][]byte{decodedBody}, []byte("\r\n\r\n"))
	return newBuf, nil
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

func isStartOfHTTPMessage(payload []byte) bool {
	if string(payload[0:4]) == "HTTP" ||
		string(payload[0:3]) == "GET" ||
		string(payload[0:4]) == "HEAD" ||
		string(payload[0:4]) == "POST" ||
		string(payload[0:3]) == "PUT" ||
		string(payload[0:5]) == "PATCH" ||
		string(payload[0:6]) == "DELETE" ||
		string(payload[0:7]) == "OPTIONS" ||
		string(payload[0:5]) == "TRACE" {
		return true
	}
	return false
}

func convertToHTTPRequest(req *http.Request) *HTTPRequest {
	// Parse request body
	payload, err := io.ReadAll(req.Body)
	if err != nil {
		fmt.Println("convertToHTTPRequest() Error reading response body:", err)
		payload = []byte{}
	}
	req.Body.Close()

	return &HTTPRequest{
		Method:      req.Method,
		Path:        req.URL.Path,
		Host:        req.Host,
		HttpVersion: "1.1",
		Headers:     req.Header,
		Payload:     payload,
	}
}

func convertToHTTPResponse(resp *http.Response, payload []byte) *HTTPResponse {
	// Extract the message (i.e. "Not Found" from "404 Not Found")
	spaceIndex := strings.Index(resp.Status, " ")
	statusMsg := ""
	if spaceIndex != -1 {
		statusMsg = resp.Status[spaceIndex+1:]
	}

	return &HTTPResponse{
		Status:      resp.StatusCode,
		StatusMsg:   statusMsg,
		HttpVersion: "1.1",
		Headers:     resp.Header,
		Payload:     payload,
	}
}
