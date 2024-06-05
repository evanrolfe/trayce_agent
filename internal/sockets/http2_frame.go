package sockets

import (
	"encoding/binary"
	"fmt"

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
	return f.raw[9:]
}

func (f *Http2Frame) Complete() bool {
	if f.Length() == 0 {
		return true
	}
	return len(f.Payload()) == int(f.Length())
}

func (f *Http2Frame) Append(raw []byte) {
	f.raw = append(f.raw, raw...)
}

func (f *Http2Frame) Headers() ([]hpack.HeaderField, error) {
	if !f.Complete() || f.Type() != 1 {
		return []hpack.HeaderField{}, fmt.Errorf("cannot parse headers for this frame")
	}

	decoder := hpack.NewDecoder(2048, nil)
	hf, err := decoder.DecodeFull(f.Payload())

	if err != nil {
		return []hpack.HeaderField{}, err
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
		fmt.Println("ERROR:", err)
		return psuedoHeaders
	}

	for _, header := range headers {
		if header.IsPseudo() {
			psuedoHeaders[header.Name] = header.Value
		}
	}
	return psuedoHeaders

}
