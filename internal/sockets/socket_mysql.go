package sockets

import (
	"fmt"
	"strings"

	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/google/uuid"
)

type SocketMysql struct {
	Common SocketCommon
	// bufEgress is a buffer for egress traffic data
	bufEgress []byte
	// bufEgress is a buffer for ingress traffic data
	bufIngress []byte
	// bufStatement is a raw query that is part of a perpared transaction, it will be sent when COMMIT is executed
	bufStatement []byte
	// bufResp is a MysqlResponse that has be been buffered, to wait until more info is received to complete it (i.e. waiting for all rows to be sent)
	bufResp *MysqlResponse
	// When a query is observed, this value is set, when the response comes, we send this value back with the response
	requestUuid string
}

func NewSocketMysqlFromUnknown(unkownSocket *SocketUnknown) SocketMysql {
	socket := SocketMysql{
		Common: SocketCommon{
			SourceAddr: unkownSocket.SourceAddr,
			DestAddr:   unkownSocket.DestAddr,
			PID:        unkownSocket.PID,
			TID:        unkownSocket.TID,
			FD:         unkownSocket.FD,
			SSL:        false,
		},
		bufEgress:  []byte{},
		bufIngress: []byte{},
	}

	return socket
}

func (socket *SocketMysql) Key() string {
	return socket.Common.Key()
}

func (socket *SocketMysql) AddFlowCallback(callback func(Flow)) {
	socket.Common.AddFlowCallback(callback)
}

func (socket *SocketMysql) ProcessDataEvent(event *events.DataEvent) {
	if socket.Common.SSL && !event.SSL() {
		return // If the socket is SSL, then ignore non-SSL events becuase they will just be encrypted gibberish
	}

	if event.SSL() && !socket.Common.SSL {
		fmt.Println("[SocketMysql] upgrading to SSL")
		socket.Common.UpgradeToSSL()
	}

	if event.Type() == events.TypeIngress {
		socket.bufIngress = append(socket.bufIngress, event.Payload()...)

		// Check ingress messages & process them
		ingressMessages := ExtractMySQLMessages(socket.bufIngress)
		if len(ingressMessages) > 0 {
			socket.clearIngress()
		}

		for _, msg := range ingressMessages {
			if msg.SequenceNum > 0 {
				socket.handleAsClient(msg)
			} else {
				socket.handleAsServer(msg)
			}
		}

	} else if event.Type() == events.TypeEgress {
		socket.bufEgress = append(socket.bufEgress, event.Payload()...)

		// Check ingress messages & process them
		egressMessages := ExtractMySQLMessages(socket.bufEgress)
		if len(egressMessages) > 0 {
			socket.clearEgress()
		}

		for _, msg := range egressMessages {
			if msg.SequenceNum > 0 {
				socket.handleAsClient(msg)
			} else {
				socket.handleAsServer(msg)
			}
		}
	}
}

func isAllowedSQLCommand(s string) bool {
	if len(s) < 4 {
		return false
	}

	// Convert first 6 chars (or whole string if shorter) to uppercase for comparison
	upTo := 6
	if len(s) < 6 {
		upTo = len(s)
	}
	prefix := strings.ToUpper(s[:upTo])

	return strings.HasPrefix(prefix, "SELECT") ||
		strings.HasPrefix(prefix, "INSERT") ||
		strings.HasPrefix(prefix, "UPDATE") ||
		strings.HasPrefix(prefix, "DELETE") ||
		strings.HasPrefix(prefix, "BEGIN") ||
		strings.HasPrefix(prefix, "COMMIT") ||
		strings.HasPrefix(prefix, "PREPAR")
}

func (socket *SocketMysql) newFlowFromQuery(rawQuery []byte) *Flow {
	sqlQuery := NewMysqlQuery(string(rawQuery))

	if !isAllowedSQLCommand(sqlQuery.Query) {
		fmt.Println("[Warn] not a handled query, skipping..")
		return nil
	}

	socket.requestUuid = uuid.NewString()
	flow := NewFlowRequest(
		socket.requestUuid,
		socket.Common.SourceAddr,
		socket.Common.DestAddr,
		"tcp",
		"mysql",
		int(socket.Common.PID),
		int(socket.Common.FD),
		&sqlQuery,
	)

	return flow
}

// func (socket *SocketMysql) processMessages(messages []MysqlMessage) {
// 	for _, msg := range messages {
// 		if socket.requestUuid == "" {
// 			// This will be a message from client => server (i.e. a query)
// 			socket.handleAsServer(msg)
// 		} else {
// 			// This will be a message from server => client (i.e. a set of rows)
// 			socket.handleAsClient(msg)
// 		}
// 	}
// }

func (socket *SocketMysql) handleAsServer(msg MysqlMessage) {
	socket.bufResp = nil // everytime a message goes from client->server, reset the buffered response

	switch msg.Type {
	case TypeMysqlQuery:
		flow := socket.newFlowFromQuery(msg.Payload)
		if flow == nil {
			return
		}
		socket.Common.sendFlowBack(*flow)

	case TypeMysqlPrepareQuery:
		socket.bufStatement = msg.Payload

	case TypeMysqlExecute:
		if len(socket.bufStatement) == 0 {
			socket.bufStatement = []byte("PREPARED STATEMENT")
		}
		flow := socket.newFlowFromQuery(socket.bufStatement)
		if flow == nil {
			return
		}
		socket.Common.sendFlowBack(*flow)
		socket.bufStatement = []byte{}

	case TypeMysqlClose:
		// TODO: Handle close, should delete the prepared statement

	default:
		return
	}
}

func (socket *SocketMysql) handleAsClient(msg MysqlMessage) {
	if socket.requestUuid == "" {
		// No query has been observed yet, so ignore this mesage
		return
	}

	if socket.bufResp == nil {
		resp := NewMysqlResponse()
		socket.bufResp = &resp
	}

	socket.bufResp.AddMessage(msg)

	if socket.bufResp.Complete() {
		flow := NewFlowResponse(
			socket.requestUuid,
			socket.Common.SourceAddr,
			socket.Common.DestAddr,
			"tcp",
			"mysql",
			int(socket.Common.PID),
			int(socket.Common.FD),
			socket.bufResp,
		)
		socket.Common.sendFlowBack(*flow)
		socket.clearBufResponse()
	}
}

func (socket *SocketMysql) clearIngress() {
	socket.bufIngress = []byte{}
}

func (socket *SocketMysql) clearEgress() {
	socket.bufEgress = []byte{}
}

func (socket *SocketMysql) clearBufResponse() {
	socket.bufResp = nil
	socket.requestUuid = ""
}

// ExtractMySQLMessages parses the provided data and returns a slice of payloads.
// Each MySQL packet is structured as follows:
//   - 3 bytes: payload length (little-endian)
//   - 1 byte:  sequence number
//   - Payload: <length> bytes of data
func ExtractMySQLMessages(data []byte) []MysqlMessage {
	messages := []MysqlMessage{}

	// Process as long as there are enough bytes to read a header
	for len(data) >= 4 {
		// The first 3 bytes are the payload length in little-endian
		length := int(data[0]) | int(data[1])<<8 | int(data[2])<<16

		// Total bytes for the packet is header (4) + payload (length)
		totalPacketSize := 4 + length

		// If we don't have enough bytes for a complete packet, break out.
		if len(data) < totalPacketSize {
			break
		}

		// Extract the payload (ignore the header in the returned slice)
		payload := make([]byte, length)
		copy(payload, data[4:totalPacketSize])

		msg := NewMysqlMessage(payload, data, int(data[3]))
		messages = append(messages, msg)

		// Remove the processed packet from the data slice
		data = data[totalPacketSize:]
	}

	return messages
}
