package sockets

import (
	"fmt"

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
	// If a flow is observed, then these are called
	flowCallbacks []func(Flow)
	// When a request is observed, this value is set, when the response comes, we send this value back with the response
	requestUuid string
	// This is the previous data processed for this unknown socket, used in detectProtocol
	prevDataEvent *events.DataEvent
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

func (socket *SocketUnknown) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

func (socket *SocketUnknown) ProcessDataEvent(event *events.DataEvent) {
}

func (socket *SocketUnknown) SetPrevDataEvent(event *events.DataEvent) {
	socket.prevDataEvent = event
}

func (socket *SocketUnknown) GetPrevDataEvent() *events.DataEvent {
	return socket.prevDataEvent
}
