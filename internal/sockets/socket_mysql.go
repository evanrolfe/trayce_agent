package sockets

import (
	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/google/uuid"
)

type SocketMysql struct {
	Common SocketCommon
	// bufEgress is a buffer for egress traffic data
	bufEgress []byte
	// bufEgress is a buffer for ingress traffic data
	bufIngress []byte
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

func (socket *SocketMysql) GetPID() uint32 {
	return socket.Common.GetPID()
}

func (socket *SocketMysql) SetPID(pid uint32) {
	socket.Common.SetPID(pid)
}

func (socket *SocketMysql) Clone() SocketI {
	return &SocketMysql{
		Common: socket.Common.Clone(),
	}
}

func (socket *SocketMysql) AddFlowCallback(callback func(Flow)) {
	socket.Common.AddFlowCallback(callback)
}

func (socket *SocketMysql) Clear() {
}

func (socket *SocketMysql) ProcessDataEvent(event *events.DataEvent) {
	if event.Type() == events.TypeIngress {
		socket.bufIngress = append(socket.bufIngress, event.Payload()...)

		// Check ingress messages & process them
		ingressMessages := ExtractMySQLMessages(socket.bufIngress)
		if len(ingressMessages) > 0 {
			socket.clearIngress()
		}
		socket.proceseMessages(ingressMessages)

	} else if event.Type() == events.TypeEgress {
		socket.bufEgress = append(socket.bufEgress, event.Payload()...)

		// Check ingress messages & process them
		egressMessages := ExtractMySQLMessages(socket.bufEgress)
		if len(egressMessages) > 0 {
			socket.clearEgress()
		}
		// fmt.Println("==============================================")
		// for i, msg := range egressMessages {
		// 	fmt.Println("Message", i, "type:", msg.Type)
		// 	fmt.Println(hex.Dump(msg.Payload))
		// }
		// fmt.Println("==============================================")
		socket.proceseMessages(egressMessages)
	}
}

func (socket *SocketMysql) proceseMessages(messages []MysqlMessage) {
	for _, msg := range messages {
		if msg.Type == TypeMysqlQuery && socket.requestUuid == "" {
			socket.requestUuid = uuid.NewString()
			sqlQuery := NewMysqlQuery(string(msg.Payload))
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
			// don't buffer on zero port because mysql never calls getsockname so the port will always be zero, we just accept that
			socket.Common.sendFlowBack(*flow, false)
		} else if socket.requestUuid != "" { // msg.Type == TypeMysqlQuery &&
			if socket.bufResp == nil {
				resp := NewMysqlResponse()
				socket.bufResp = &resp
			}
			// fmt.Println("Message response type:", msg.Type)
			// fmt.Println(hex.Dump(msg.Payload))

			if msg.Type == TypeMysqlQuery { // this is a column being sent
				socket.bufResp.AddColumnPayload(msg.Payload)
			} else if msg.Type == TypeMysqlRow {
				socket.bufResp.AddRowPayload(msg.Payload)

			} else if msg.Type == TypeMysqlEOF {
				socket.bufResp.AddEOF()
			}

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
				socket.Common.sendFlowBack(*flow, false)
				socket.clearBufResponse()
			}
		} // else if msg.Type == TypeMysqlRow && socket.requestUuid != "" {
		// 	fmt.Println("Message query row type:", msg.Type)
		// 	fmt.Println(hex.Dump(msg.Payload))
		// }
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
//   - 1 byte:  sequence number (ignored in this function)
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

		msg := NewMysqlMessage(payload)
		messages = append(messages, msg)

		// Remove the processed packet from the data slice
		data = data[totalPacketSize:]
	}

	return messages
}
