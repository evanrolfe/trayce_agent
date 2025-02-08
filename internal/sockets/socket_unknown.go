package sockets

import (
	"fmt"
	"strings"

	"github.com/evanrolfe/trayce_agent/internal/events"
)

type SocketUnknown struct {
	SourceAddr string
	DestAddr   string
	Protocol   string
	PID        uint32
	TID        uint32
	FD         uint32
	SSL        bool
	// Stores
	activeFrame *Http2Frame
	activeFlow  *Flow
	// If a flow is observed, then these are called
	flowCallbacks []func(Flow)
	// When a request is observed, this value is set, when the response comes, we send this value back with the response
	requestUuid string
	// This is the previous data processed for this unknown socket, used in detectProtocol
	prevDataEvent *events.DataEvent
}

func NewSocketUnknown(event *events.ConnectEvent) SocketUnknown {
	socket := SocketUnknown{
		SourceAddr:  event.SourceAddr(),
		DestAddr:    event.DestAddr(),
		PID:         event.PID,
		TID:         event.TID,
		FD:          event.FD,
		SSL:         false,
		requestUuid: "",
	}

	return socket
}

func NewSocketUnknownFromData(event *events.DataEvent) SocketUnknown {
	socket := SocketUnknown{
		SourceAddr:  event.SourceAddr(),
		DestAddr:    event.DestAddr(),
		PID:         event.PID,
		TID:         event.TID,
		FD:          event.FD,
		SSL:         false,
		requestUuid: "",
	}

	return socket
}

func (socket *SocketUnknown) Key() string {
	return fmt.Sprintf("%s->%s", socket.SourceAddr, socket.DestAddr)
}

func (socket *SocketUnknown) GetPID() uint32 {
	return socket.PID
}

func (socket *SocketUnknown) SetPID(pid uint32) {
	socket.PID = pid
}

func (socket *SocketUnknown) Clone() SocketI {
	return &SocketUnknown{
		SourceAddr:  socket.SourceAddr,
		DestAddr:    socket.DestAddr,
		PID:         socket.PID,
		TID:         socket.TID,
		FD:          socket.FD,
		SSL:         socket.SSL,
		requestUuid: "",
	}
}

func (socket *SocketUnknown) Clear() {
}

func (socket *SocketUnknown) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

func (socket *SocketUnknown) ProcessConnectEvent(event *events.ConnectEvent) {
}

func (socket *SocketUnknown) ProcessGetsocknameEvent(event *events.GetsocknameEvent) {
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

func (socket *SocketUnknown) ProcessDataEvent(event *events.DataEvent) {
}

func (socket *SocketUnknown) SetPrevDataEvent(event *events.DataEvent) {
	socket.prevDataEvent = event
}

func (socket *SocketUnknown) GetPrevDataEvent() *events.DataEvent {
	return socket.prevDataEvent
}
