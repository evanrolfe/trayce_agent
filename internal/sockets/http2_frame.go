package sockets

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const (
	frameTypeData    = 0
	frameTypeHeaders = 1
)

type Http2Frame struct {
	raw []byte
}

type Http2Flags struct {
	EndStream  bool
	EndHeaders bool
	Padded     bool
	Priority   bool
}

// ParseBytesToFrames parses a byte array into zero or more complete Http2Frames. If there is an incomplete frame
// then the for it are return as the second return value.
// Its implemented like this because Go can send multiple frames in the same call, or send the same frame over multiple calls.
func ParseBytesToFrames(raw []byte) ([]*Http2Frame, []byte) {
	byteBuf := []byte{}
	frames := []*Http2Frame{}

	// points to the end of the last complete frame
	indexPointer := 0
	for i, b := range raw {
		byteBuf = append(byteBuf, b)
		frame := NewHttp2Frame(byteBuf)

		if frame.Complete() {
			indexPointer = i + 1 // Set the pointer to the start of the next frame
			byteBuf = []byte{}   // clear the buffer
			frames = append(frames, frame)
		}
	}

	// work out the remainder bytes
	remainder := []byte{}
	fmt.Println("indexPointer:", indexPointer)
	for i := indexPointer; i < len(raw); i++ {
		remainder = append(remainder, raw[i])
	}

	return frames, remainder
}

func NewHttp2Frame(raw []byte) *Http2Frame {
	return &Http2Frame{raw: raw}
}

func (f *Http2Frame) Length() uint32 {
	return binary.BigEndian.Uint32([]byte{0, f.raw[0], f.raw[1], f.raw[2]})
}

func (f *Http2Frame) Type() uint8 {
	return uint8(f.raw[3])

}

func (f *Http2Frame) Flags() Http2Flags {
	flagByte := f.raw[4]

	return Http2Flags{
		EndStream:  flagByte&0x1 != 0,
		EndHeaders: flagByte&0x4 != 0,
		Padded:     flagByte&0x8 != 0,
		Priority:   flagByte&0x20 != 0,
	}
}

func (f *Http2Frame) StreamID() uint32 {
	return binary.BigEndian.Uint32(f.raw[5:9]) & 0x7FFFFFFF // Mask the most significant bit
}

func (f *Http2Frame) Payload() []byte {
	if len(f.raw) < 9 {
		return []byte{}
	}

	return f.raw[9:]
}

// Cases (first 3 bytes are the length):
//
// [00 00 10] => incomplete
// [00 00 00] => incomplete
// [00 00 00 04 01] => incomplete
// [00 00 00 04 01 00 00 00 00] => complete
// [00 00 03 04 01 00 00 00 00 01 02 03] => complete
func (f *Http2Frame) Complete() bool {
	// The first 3 bytes are the length so we need this to know if its complete or not
	if len(f.raw) < 3 {
		return false
	}

	if f.Length() > 0 {
		return len(f.Payload()) == int(f.Length())
	} else {
		return len(f.raw) == 9
	}
}

func (f *Http2Frame) Append(raw []byte) {
	f.raw = append(f.raw, raw...)
}

func (f *Http2Frame) ConvertToFlowRequest() (FlowRequest, error) {
	if !f.Complete() || f.Type() != 1 {
		return nil, fmt.Errorf("ERROR: cannot convert incomplete or non-header frame to HTTPRequest")
	}

	// parse psuedo headers
	psuedoHeaders := f.psuedoHeaders()
	if psuedoHeaders[":method"] == "" || psuedoHeaders[":path"] == "" {
		return nil, fmt.Errorf("ERROR: cannot convert frame to HTTPRequest, missing :path header")
	}

	// parse headers
	headers, err := f.Headers()
	if err != nil {
		return nil, fmt.Errorf("ERROR from f.Headers(): %v", err)
	}

	// determine http or grpc
	isGRPC := false
	for _, header := range headers {
		if strings.ToLower(header.Name) == "content-type" && strings.Contains(header.Value, "application/grpc") {
			isGRPC = true
		}
	}

	if isGRPC {
		grpcReq := &GRPCRequest{}
		grpcReq.Path = psuedoHeaders[":path"]
		grpcReq.Headers = convertHPackHeaders(headers)

		return grpcReq, nil
	} else {
		httpReq := &HTTPRequest{}
		httpReq.HttpVersion = "2"
		httpReq.Method = psuedoHeaders[":method"]
		httpReq.Path = psuedoHeaders[":path"]
		httpReq.Host = psuedoHeaders[":authority"]
		httpReq.Headers = convertHPackHeaders(headers)

		return httpReq, nil
	}
}

func (f *Http2Frame) ConvertToFlowResponse() (FlowResponse, error) {
	if !f.Complete() || f.Type() != 1 {
		return nil, fmt.Errorf("cannot convert incomplete or non-header frame to FlowResponse")
	}

	// parse psuedo headers, extract status
	psuedoHeaders := f.psuedoHeaders()
	if psuedoHeaders[":status"] == "" {
		return nil, fmt.Errorf("ERROR: cannot convert frame to FlowResponse, missing :status header")
	}
	status, err := strconv.Atoi(psuedoHeaders[":status"])

	// pare headers
	headers, err := f.Headers()
	if err != nil {
		return nil, fmt.Errorf("ERROR from f.Headers(): %v", err)
	}

	// determine http or grpc
	isGRPC := false
	for _, header := range headers {
		if strings.ToLower(header.Name) == "content-type" && strings.Contains(header.Value, "application/grpc") {
			isGRPC = true
		}
	}

	if isGRPC {
		grpcResp := &GRPCResponse{}
		grpcResp.Headers = convertHPackHeaders(headers)
		grpcResp.Payload = []byte{}

		return grpcResp, nil
	} else {
		httpResp := &HTTPResponse{}
		httpResp.Status = status
		httpResp.HttpVersion = "2"
		httpResp.Headers = convertHPackHeaders(headers)
		httpResp.Payload = []byte{}

		return httpResp, nil
	}
}

func (f *Http2Frame) Headers() ([]hpack.HeaderField, error) {
	if !f.Complete() || f.Type() != 1 {
		return []hpack.HeaderField{}, fmt.Errorf("cannot parse headers for this frame")
	}

	decoder := hpack.NewDecoder(4096, nil)
	hf, err := decoder.DecodeFull(f.Payload())

	if err != nil {
		return []hpack.HeaderField{}, fmt.Errorf("decoder.DecodeFull(): %w", err)
	}

	return hf, nil
}

// HeadersText converts this to an HTTP1.1 formatted message
func (f *Http2Frame) HeadersText() string {
	if !f.Complete() || f.Type() != 1 {
		return ""
	}

	// Gather the psuedo headers map
	psuedoHeaders := f.psuedoHeaders()

	headersText := ""
	if psuedoHeaders[":method"] != "" {
		// Build the HTTP request line
		headersText += fmt.Sprintf("%s %s HTTP/2\r\n", psuedoHeaders[":method"], psuedoHeaders[":path"])
		headersText += fmt.Sprintf("host: %s\r\n", psuedoHeaders[":authority"])

	} else if psuedoHeaders[":status"] != "" {
		// Build the HTTP response line
		headersText += fmt.Sprintf("HTTP/2 %s\r\n", psuedoHeaders[":status"])
	}

	// Add the remaining non-psuedo headers
	headers, err := f.Headers()
	if err != nil {
		fmt.Println("ERROR:", err)
		return fmt.Sprintf("Error parsing headers: %s", err.Error())
	}
	for _, header := range headers {
		if header.IsPseudo() {
			continue
		}

		headersText += fmt.Sprintf("%s: %s\r\n", header.Name, header.Value)
	}

	headersText += "\r\n"

	return headersText
}

func (f *Http2Frame) IsRequest() bool {
	return f.psuedoHeaders()[":method"] != ""
}

func (f *Http2Frame) psuedoHeaders() map[string]string {
	psuedoHeaders := map[string]string{}

	headers, err := f.Headers()
	if err != nil {
		fmt.Println("ERROR from f.Headers():", err)
		return psuedoHeaders
	}

	for _, header := range headers {
		if header.IsPseudo() {
			psuedoHeaders[header.Name] = header.Value
		}
	}
	return psuedoHeaders

}

func convertHPackHeaders(headers []hpack.HeaderField) map[string][]string {
	newHeaders := map[string][]string{}

	for _, header := range headers {
		if header.IsPseudo() {
			continue
		}
		h := newHeaders[header.Name]
		if h == nil {
			newHeaders[header.Name] = []string{header.Value}
		} else {
			h = append(h, header.Value)
		}
	}

	return newHeaders
}
