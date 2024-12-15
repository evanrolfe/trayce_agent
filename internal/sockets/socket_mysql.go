package sockets

import (
	"fmt"
	"strings"

	"github.com/evanrolfe/trayce_agent/internal/events"
)

type SocketMysql struct {
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

func NewSocketMysqlFromUnknown(unkownSocket *SocketUnknown) SocketMysql {
	socket := SocketMysql{
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
func (socket *SocketMysql) Key() string {
	return fmt.Sprintf("%d-%d", socket.PID, socket.FD)
}

func (socket *SocketMysql) GetPID() uint32 {
	return socket.PID
}

func (socket *SocketMysql) SetPID(pid uint32) {
	socket.PID = pid
}

func (socket *SocketMysql) Clone() SocketI {
	return &SocketMysql{
		SourceAddr:  socket.SourceAddr,
		DestAddr:    socket.DestAddr,
		PID:         socket.PID,
		TID:         socket.TID,
		FD:          socket.FD,
		SSL:         socket.SSL,
		requestUuid: "",
	}
}

func (socket *SocketMysql) Clear() {
}

func (socket *SocketMysql) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

func (socket *SocketMysql) ProcessConnectEvent(event *events.ConnectEvent) {
}

func (socket *SocketMysql) ProcessGetsocknameEvent(event *events.GetsocknameEvent) {
	// Technically mysql never sends this event, but we have the code here for completeness i guess
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

func (socket *SocketMysql) ProcessDataEvent(event *events.DataEvent) {
}
