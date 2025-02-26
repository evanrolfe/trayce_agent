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

func (sk *SocketMysql) Key() string {
	return sk.Common.Key()
}

func (sk *SocketMysql) AddFlowCallback(callback func(Flow)) {
	sk.Common.AddFlowCallback(callback)
}

func (sk *SocketMysql) ProcessDataEvent(event *events.DataEvent) {
	if sk.Common.SSL && !event.SSL() {
		return // If the socket is SSL, then ignore non-SSL events becuase they will just be encrypted gibberish
	}

	if event.SSL() && !sk.Common.SSL {
		fmt.Println("[SocketMysql] upgrading to SSL")
		sk.Common.UpgradeToSSL()
	}

	if event.Type() == events.TypeIngress {
		sk.bufIngress = append(sk.bufIngress, event.Payload()...)

		// Check ingress messages & process them
		ingressMessages := ExtractMySQLMessages(sk.bufIngress)
		if len(ingressMessages) > 0 {
			sk.clearIngress()
		}

		for _, msg := range ingressMessages {
			if msg.SequenceNum > 0 {
				sk.handleAsClient(msg)
			} else {
				sk.handleAsServer(msg)
			}
		}

	} else if event.Type() == events.TypeEgress {
		sk.bufEgress = append(sk.bufEgress, event.Payload()...)

		// Check ingress messages & process them
		egressMessages := ExtractMySQLMessages(sk.bufEgress)
		if len(egressMessages) > 0 {
			sk.clearEgress()
		}

		for _, msg := range egressMessages {
			if msg.SequenceNum > 0 {
				sk.handleAsClient(msg)
			} else {
				sk.handleAsServer(msg)
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
		strings.HasPrefix(prefix, "PREPAR") ||
		strings.HasPrefix(prefix, "START")
}

func (sk *SocketMysql) newFlowFromQuery(rawQuery []byte) *Flow {
	sqlQuery := NewMysqlQuery(rawQuery)

	if !isAllowedSQLCommand(sqlQuery.Query) {
		fmt.Println("[Warn] not a handled query, skipping..")
		return nil
	}

	sk.requestUuid = uuid.NewString()
	flow := NewFlowRequest(
		sk.requestUuid,
		sk.Common.SourceAddr,
		sk.Common.DestAddr,
		"tcp",
		"mysql",
		int(sk.Common.PID),
		int(sk.Common.FD),
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

func (sk *SocketMysql) handleAsServer(msg MysqlMessage) {
	sk.bufResp = nil // everytime a message goes from client->server, reset the buffered response
	switch msg.Type {
	case TypeMysqlQuery:
		flow := sk.newFlowFromQuery(msg.Payload)
		if flow == nil {
			return
		}
		sk.Common.sendFlowBack(*flow)

	case TypeMysqlPrepareQuery:
		sk.bufStatement = msg.Payload

	case TypeMysqlExecute:
		if len(sk.bufStatement) == 0 {
			sk.bufStatement = []byte("PREPARED STATEMENT")
		}
		flow := sk.newFlowFromQuery(sk.bufStatement)
		if flow == nil {
			return
		}
		sk.Common.sendFlowBack(*flow)
		sk.bufStatement = []byte{}

	case TypeMysqlClose:
		// TODO: Handle close, should delete the prepared statement

	default:
		return
	}
}

func (sk *SocketMysql) handleAsClient(msg MysqlMessage) {
	if sk.requestUuid == "" {
		// No query has been observed yet, so ignore this mesage
		return
	}

	if sk.bufResp == nil {
		resp := NewMysqlResponse()
		sk.bufResp = &resp
	}

	sk.bufResp.AddMessage(msg)

	if sk.bufResp.Complete() {
		flow := NewFlowResponse(
			sk.requestUuid,
			sk.Common.SourceAddr,
			sk.Common.DestAddr,
			"tcp",
			"mysql",
			int(sk.Common.PID),
			int(sk.Common.FD),
			sk.bufResp,
		)
		sk.Common.sendFlowBack(*flow)
		sk.clearBufResponse()
	}
}

func (sk *SocketMysql) clearIngress() {
	sk.bufIngress = []byte{}
}

func (sk *SocketMysql) clearEgress() {
	sk.bufEgress = []byte{}
}

func (sk *SocketMysql) clearBufResponse() {
	sk.bufResp = nil
	sk.requestUuid = ""
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
