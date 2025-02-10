package sockets

import (
	"bytes"
	"slices"
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
	// The connection will likely already have been established by the time we get bytes so we can't realistically check
	// for the postgres start identifiers like version 3.0: 0x00,0x03,0x00,0x00
	// Instead we just check the first byte for message identifiers
	if slices.Contains([]string{"Q", "P", "B", "X"}, string(raw[0])) {
		return PSQL
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
