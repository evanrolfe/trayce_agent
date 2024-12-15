package sockets

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/evanrolfe/trayce_agent/internal/events"
)

type SocketPsql struct {
	SourceAddr string
	DestAddr   string
	Protocol   string
	PID        uint32
	TID        uint32
	FD         uint32
	SSL        bool
	// If a flow is observed, then these are called
	flowCallbacks []func(Flow)
	// When a request is observed, this value is set, when the response comes, we send this value back with the response
	requestUuid string
}

func NewSocketPsqlFromUnknown(unkownSocket *SocketUnknown) SocketPsql {
	socket := SocketPsql{
		SourceAddr:  unkownSocket.SourceAddr,
		DestAddr:    unkownSocket.DestAddr,
		PID:         unkownSocket.PID,
		TID:         unkownSocket.TID,
		FD:          unkownSocket.FD,
		SSL:         false,
		requestUuid: "",
	}

	return socket
}
func (socket *SocketPsql) Key() string {
	return fmt.Sprintf("%d-%d", socket.PID, socket.FD)
}

func (socket *SocketPsql) GetPID() uint32 {
	return socket.PID
}

func (socket *SocketPsql) SetPID(pid uint32) {
	socket.PID = pid
}

func (socket *SocketPsql) Clone() SocketI {
	return &SocketPsql{
		SourceAddr:  socket.SourceAddr,
		DestAddr:    socket.DestAddr,
		PID:         socket.PID,
		TID:         socket.TID,
		FD:          socket.FD,
		SSL:         socket.SSL,
		requestUuid: "",
	}
}

func (socket *SocketPsql) Clear() {
}

func (socket *SocketPsql) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

func (socket *SocketPsql) ProcessConnectEvent(event *events.ConnectEvent) {
}

func (socket *SocketPsql) ProcessGetsocknameEvent(event *events.GetsocknameEvent) {
	sourceAddrSplit := strings.Split(socket.SourceAddr, ":")
	sourcePort := sourceAddrSplit[1]

	destAddrSplit := strings.Split(socket.DestAddr, ":")
	destPort := destAddrSplit[1]

	if sourcePort == "0" {
		socket.SourceAddr = event.Addr()
	} else if destPort == "0" {
		socket.DestAddr = event.Addr()
	}
}

func (socket *SocketPsql) ProcessDataEvent(event *events.DataEvent) {
	payload := event.Payload()
	if payload[0] == 0x51 {
		fmt.Println("================> QUERY:\n", hex.Dump(event.Payload()))
		msg := PsqlMessage{}
		msg.Decode(payload)

		fmt.Printf("Type: 0x%X, Length: %d\nQuery:", msg.Type, msg.Length)
		fmt.Println(string(msg.Payload))
		if string(msg.Payload) == ";" {
			// This is a query with just ";" so we ignore it
			return
		}
	}
}
