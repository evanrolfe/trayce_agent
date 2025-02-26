package sockets

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/google/uuid"
)

type SocketPsql struct {
	Common SocketCommon
	// bufQueryFlow is a Flow that has be been buffered, to wait until more info is received to complete it (i.e. a prepared query waiting for the args to come in a Bind message)
	bufQueryFlow *Flow
	// bufQueryFlow is a Flow that has be been buffered, to wait until more info is received to complete it (i.e. waiting for all rows to be sent)
	bufRespFlow *Flow
	// When a query is observed, this value is set, when the response comes, we send this value back with the response
	requestUuid string
}

func NewSocketPsqlFromUnknown(unkownSocket *SocketUnknown) SocketPsql {
	socket := SocketPsql{
		Common: SocketCommon{
			SourceAddr: unkownSocket.SourceAddr,
			DestAddr:   unkownSocket.DestAddr,
			PID:        unkownSocket.PID,
			TID:        unkownSocket.TID,
			FD:         unkownSocket.FD,
			SSL:        false,
		},
		bufQueryFlow: nil,
	}

	return socket
}

func (socket *SocketPsql) Key() string {
	return socket.Common.Key()
}

func (socket *SocketPsql) AddFlowCallback(callback func(Flow)) {
	socket.Common.AddFlowCallback(callback)
}

func (socket *SocketPsql) ProcessDataEvent(event *events.DataEvent) {
	if socket.Common.SSL && !event.SSL() {
		return // If the socket is SSL, then ignore non-SSL events becuase they will just be encrypted gibberish
	}

	if event.SSL() && !socket.Common.SSL {
		fmt.Println("[SocketPsql] upgrading to SSL")
		socket.Common.UpgradeToSSL()
	}

	payload := event.Payload()
	messages := ExtractMessages(payload)

	for _, msg := range messages {
		switch msg.Type {
		case TypeQuery:
			if bytes.Equal(msg.Payload, []byte{0x3b, 0x00}) {
				// This is a query with just ";" so we ignore it
				return
			}
			sqlQuery := NewPSQLQuery(string(trimNonASCII(msg.Payload)))
			socket.newFlowFromQuery(sqlQuery)
			socket.Common.sendFlowBack(*socket.bufQueryFlow)
		case TypeParse:
			_, queryStr, err := extractNamedQuery(msg.Payload)
			if err != nil {
				fmt.Println("[Error] [SocketPsql] could not extract named query")
				return
			}

			sqlQuery := NewPSQLQuery(queryStr)
			socket.newFlowFromQuery(sqlQuery)
		case TypeBind:
			if socket.bufQueryFlow == nil {
				// In a Postgres named query, we will just get a Bind message and the name of the query, but not the query itself
				// so in this case we just create a PSQLQuery with the query name as query
				sqlQuery := NewPSQLQuery("PREPARED STATEMENT")
				socket.newFlowFromQuery(sqlQuery)
			}

			query, ok := socket.bufQueryFlow.Request.(*PSQLQuery)
			if !ok {
				fmt.Println("[Error] [SocketPsql] could not convert FlowRequest to SQLQuery")
				return
			}
			query.AddPayload(msg.Payload)
			socket.Common.sendFlowBack(*socket.bufQueryFlow)
			socket.clearBufQueryFlow()
		case TypeRowDesc:
			sqlResp, err := PSQLResponseFromRowDescription(msg.Payload)
			if err != nil {
				fmt.Println("[Error] [SocketPsql] extractColumnNames():", err)
				return
			}
			flow := NewFlowResponse(
				socket.requestUuid,
				socket.Common.SourceAddr,
				socket.Common.DestAddr,
				"tcp",
				"psql",
				int(socket.Common.PID),
				int(socket.Common.FD),
				&sqlResp,
			)
			// Buffer the flow until we receive the all the rows in this response
			socket.bufRespFlow = flow
		case TypeDataRow:
			if socket.bufRespFlow == nil {
				fmt.Println("[Error] [SocketPsql] data row message received but there is no buffered flow!")
				return
			}
			resp, ok := socket.bufRespFlow.Response.(*PSQLResponse)
			if !ok {
				fmt.Println("[Error] [SocketPsql] could not convert FlowResponse to SQLResponse")
				return
			}
			resp.AddPayload(msg.Payload) // TODO: Make this work
		case TypeCommandComplete:
			if socket.bufRespFlow == nil {
				fmt.Println("[Error] [SocketPsql] bind message received but there is no buffered flow!")
				return
			}
			socket.Common.sendFlowBack(*socket.bufRespFlow)
			socket.clearBufRespFlow()
		}
	}
}

func (socket *SocketPsql) newFlowFromQuery(sqlQuery PSQLQuery) {
	socket.requestUuid = uuid.NewString()
	flow := NewFlowRequest(
		socket.requestUuid,
		socket.Common.SourceAddr,
		socket.Common.DestAddr,
		"tcp",
		"psql",
		int(socket.Common.PID),
		int(socket.Common.FD),
		&sqlQuery,
	)
	// Buffer the flow until we receive the arguments of this prepared query in a postgres bind message
	socket.bufQueryFlow = flow
}

func (socket *SocketPsql) clearBufQueryFlow() {
	socket.bufQueryFlow = nil
}

func (socket *SocketPsql) clearBufRespFlow() {
	socket.bufRespFlow = nil
}

// extractMessages parses a PostgreSQL message stream and extracts individual messages
func ExtractMessages(data []byte) []PsqlMessage {
	var messages []PsqlMessage
	reader := bytes.NewReader(data)

	for {
		// Check if we have enough bytes for at least message type + length
		if reader.Len() < 5 {
			// Not enough bytes to read another message
			break
		}

		// Read the message type
		var msgType byte
		if err := binary.Read(reader, binary.BigEndian, &msgType); err != nil {
			// Can't read further
			break
		}

		// Read the message length (4 bytes)
		var length int32
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			// Can't read further
			break
		}

		// Calculate the payload size
		payloadSize := int(length) - 4
		if payloadSize < 0 || payloadSize > reader.Len() {
			// The length is invalid or incomplete payload
			// Stop parsing here since we can't form a valid message
			break
		}

		// Read the payload
		payload := make([]byte, payloadSize)
		if _, err := reader.Read(payload); err != nil {
			// Incomplete payload
			break
		}

		// Reconstruct the full message: type + length + payload
		msgRaw := make([]byte, 1+4+payloadSize)
		msgRaw[0] = msgType
		binary.BigEndian.PutUint32(msgRaw[1:5], uint32(length))
		copy(msgRaw[5:], payload)

		// Append this message to our slice
		msg := PsqlMessage{}
		msg.Decode(msgRaw)
		messages = append(messages, msg)
	}

	return messages
}

// extractBindArgsFromPayload parses the Bind message payload (without the first 5 bytes for type+length).
func extractBindArgsFromPayload(msg []byte) ([]string, error) {
	buf := bytes.NewBuffer(msg)

	// Read portalName (null-terminated string)
	portalName, err := readNullTerminatedString(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read portal name: %w", err)
	}
	_ = portalName // not needed

	// Read statementName (null-terminated string)
	statementName, err := readNullTerminatedString(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read statement name: %w", err)
	}
	_ = statementName // not needed

	// Read number of parameter format codes (int16)
	var paramFormatCount int16
	if err := binary.Read(buf, binary.BigEndian, &paramFormatCount); err != nil {
		return nil, fmt.Errorf("failed to read param format count: %w", err)
	}

	// Read param format codes
	paramFormats := make([]int16, paramFormatCount)
	for i := 0; i < int(paramFormatCount); i++ {
		if err := binary.Read(buf, binary.BigEndian, &paramFormats[i]); err != nil {
			return nil, fmt.Errorf("failed to read param format code: %w", err)
		}
	}

	// Read the number of parameters (int16)
	var paramCount int16
	if err := binary.Read(buf, binary.BigEndian, &paramCount); err != nil {
		return nil, fmt.Errorf("failed to read param count: %w", err)
	}

	params := make([]string, 0, paramCount)

	// Read each parameter
	for i := 0; i < int(paramCount); i++ {
		var paramLen int32
		if err := binary.Read(buf, binary.BigEndian, &paramLen); err != nil {
			return nil, fmt.Errorf("failed to read param length: %w", err)
		}

		if paramLen == -1 {
			// NULL parameter
			params = append(params, "")
			continue
		}

		if int(paramLen) > buf.Len() {
			return nil, fmt.Errorf("not enough data for parameter value")
		}

		paramValue := make([]byte, paramLen)
		if _, err := buf.Read(paramValue); err != nil {
			return nil, fmt.Errorf("failed to read param value: %w", err)
		}

		// Convert the parameter bytes to string
		params = append(params, string(paramValue))
	}

	// Read number of result format codes
	var resultFormatCount int16
	if err := binary.Read(buf, binary.BigEndian, &resultFormatCount); err != nil {
		return nil, fmt.Errorf("failed to read result format count: %w", err)
	}

	// Read result format codes if any
	for i := 0; i < int(resultFormatCount); i++ {
		var code int16
		if err := binary.Read(buf, binary.BigEndian, &code); err != nil {
			return nil, fmt.Errorf("failed to read result format code: %w", err)
		}
	}

	return params, nil
}

func readNullTerminatedString(buf *bytes.Buffer) (string, error) {
	strBytes, err := buf.ReadBytes(0)
	if err != nil {
		return "", err
	}

	// Remove the trailing null byte
	if len(strBytes) > 0 {
		strBytes = strBytes[:len(strBytes)-1]
	}

	return string(strBytes), nil
}

func extractNamedQuery(payload []byte) (string, string, error) {
	// Find the position of the first null byte
	nullPos := bytes.IndexByte(payload, 0)
	if nullPos == -1 {
		return "", "", fmt.Errorf("no null terminator found in payload")
	}

	// Extract the name (everything before the null byte)
	name := string(payload[:nullPos])

	// Extract the query (everything after the null byte, until the next null byte or end)
	queryStart := nullPos + 1
	if queryStart >= len(payload) {
		return "", "", fmt.Errorf("no query found after statement name")
	}

	// Find the end of the query (either at the next null byte or end of payload)
	queryEnd := bytes.IndexByte(payload[queryStart:], 0)
	if queryEnd == -1 {
		queryEnd = len(payload) - queryStart
	}
	query := string(payload[queryStart : queryStart+queryEnd])

	return name, query, nil
}
