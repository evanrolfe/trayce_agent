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

func (sk *SocketUnknown) Key() string {
	return fmt.Sprintf("%s->%s", sk.SourceAddr, sk.DestAddr)
}

func (sk *SocketUnknown) AddFlowCallback(callback func(Flow)) {
	sk.flowCallbacks = append(sk.flowCallbacks, callback)
}

func (sk *SocketUnknown) ProcessDataEvent(event *events.DataEvent) {
}

func (sk *SocketUnknown) SetPrevDataEvent(event *events.DataEvent) {
	sk.prevDataEvent = event
}

func (sk *SocketUnknown) GetPrevDataEvent() *events.DataEvent {
	return sk.prevDataEvent
}
