package sockets

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	if isPSQLMessage(raw) {
		return PSQL
	}

	// Mysql (if the header packet is sent separately from the payload)
	if len(prevRaw) == 4 {
		// The first 3 bytes represent the payload length in little-endian order.
		headerLen := int(prevRaw[0]) | int(prevRaw[1])<<8 | int(prevRaw[2])<<16
		msgType := raw[0]

		if len(raw) == headerLen && isDesiredMySQLMessage(msgType) {
			return MySQL
		}
	}

	// Mysql (if the header packet is sent with the payload in a single message)
	if len(raw) > 4 {
		headerLen := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16
		msgType := raw[4]

		if len(raw) == headerLen+4 && isDesiredMySQLMessage(msgType) {
			return MySQL
		}
	}

	return Unknown
}

// isPSQLMessage parses the bytes as if they were a postgres message, it assume the first byte is the message type and
// the next four bytes are the message length. It then looks at the last byte of the payload and if that is 0x00
// (Null terminator) then its assumed to be postgres.
// NOTE: There is a small chance this could give a false positive.
// The connection will likely already have been established by the time we get bytes so we can't realistically check
// for the postgres start identifiers like version 3.0: 0x00,0x03,0x00,0x00
func isPSQLMessage(raw []byte) bool {
	if !slices.Contains([]string{"Q", "P", "B", "X"}, string(raw[0])) {
		return false
	}

	reader := bytes.NewReader(raw)
	// Check if we have enough bytes for at least message type + length
	if reader.Len() < 5 {
		// Not enough bytes to read another message
		return false
	}

	// Read the message type
	var msgType byte
	if err := binary.Read(reader, binary.BigEndian, &msgType); err != nil {
		// Can't read further
		return false
	}
	fmt.Printf("msgType: %x\n", msgType)

	// Read the message length (4 bytes)
	var length int32
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		// Can't read further
		return false
	}
	fmt.Printf("length: %d\n", length)

	// Calculate the payload size
	payloadSize := int(length) - 4
	if payloadSize < 0 || payloadSize > reader.Len() {
		// The length is invalid or incomplete payload
		// Stop parsing here since we can't form a valid message
		return false
	}

	// Read the payload
	payload := make([]byte, payloadSize)
	if _, err := reader.Read(payload); err != nil {
		// Incomplete payload
		return false
	}

	lastByte := payload[len(payload)-1]

	return lastByte == 0x00
}

func isDesiredMySQLMessage(msgType byte) bool {
	desiredTypes := []byte{
		TypeMysqlQuery,
		TypeMysqlPrepareQuery,
		TypeMysqlExecute,
		TypeMysqlClose,
	}

	return slices.Contains(desiredTypes, msgType)
}
