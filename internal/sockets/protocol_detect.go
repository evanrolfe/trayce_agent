package sockets

import (
	"bytes"
)

// See: https://github.com/pixie-io/pixie/blob/main/src/stirling/source_connectors/socket_tracer/bcc_bpf/protocol_inference.h

const (
	HTTP    = "http"
	HTTP2   = "http2"
	PSQL    = "psql"
	MySQL   = "mysql"
	Unknown = "unknown"
)

var (
	http2MagicString = []byte{0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32, 0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A}
)

func detectProtocol(raw []byte, prevRaw []byte) string {
	// HTTP1.1
	if len(raw) >= 3 && string(raw[0:3]) == "GET" {
		return HTTP
	}
	if len(raw) >= 4 && string(raw[0:4]) == "HEAD" {
		return HTTP
	}
	if len(raw) >= 4 && string(raw[0:4]) == "POST" {
		return HTTP
	}
	if len(raw) >= 5 && string(raw[0:5]) == "PATCH" {
		return HTTP
	}
	if len(raw) >= 3 && string(raw[0:3]) == "PUT" {
		return HTTP
	}
	if len(raw) >= 6 && string(raw[0:6]) == "DELETE" {
		return HTTP
	}
	if len(raw) >= 7 && string(raw[0:7]) == "OPTIONS" {
		return HTTP
	}
	if len(raw) >= 5 && string(raw[0:5]) == "TRACE" {
		return HTTP
	}

	// HTTP2
	if len(raw) >= 24 && bytes.Equal(raw[0:24], http2MagicString) {
		return HTTP2
	}

	// Postgres
	// 16 is an arbitrary number to try and ensure it has both the protocol version & user key in the payload
	// It would be wise to detect protocol on the socket's buffer rather than an individual event
	if len(raw) >= 16 {
		protocolSeq := []byte{0x00, 0x03, 0x00, 0x00} // assumes version 3.0
		userKeySeq := []byte{0x75, 0x73, 0x65, 0x72}  // check if the "user" key exists in the payload

		if bytes.Contains(raw, protocolSeq) && bytes.Contains(raw, userKeySeq) {
			return PSQL
		}
	}

	// Mysql
	if len(prevRaw) == 4 {
		// The first 3 bytes represent the payload length in little-endian order.
		headerLen := int(prevRaw[0]) | int(prevRaw[1])<<8 | int(prevRaw[2])<<16

		if len(raw) == headerLen {
			return MySQL
		}
	}

	return Unknown
}
