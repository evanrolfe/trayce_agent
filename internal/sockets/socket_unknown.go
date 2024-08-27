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
	// Stores
	activeFrame *Http2Frame
	activeFlow  *Flow
	// If a flow is observed, then these are called
	flowCallbacks []func(Flow)
	// When a request is observed, this value is set, when the response comes, we send this value back with the response
	requestUuid string
}

func NewSocketUnknown(event *events.ConnectEvent) SocketUnknown {
	socket := SocketUnknown{
		SourceAddr:  "unknown",
		PID:         event.PID,
		TID:         event.TID,
		FD:          event.FD,
		SSL:         false,
		requestUuid: "",
	}

	socket.SourceAddr = "" // TODO
	socket.DestAddr = ""   // TODO

	return socket
}

func (socket *SocketUnknown) Key() string {
	return fmt.Sprintf("%d-%d", socket.PID, socket.FD)
}

func (socket *SocketUnknown) Clear() {
}

func (socket *SocketUnknown) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

// ProcessConnectEvent is called when the connect event arrives after the data event
func (socket *SocketUnknown) ProcessConnectEvent(event *events.ConnectEvent) {
	socket.SourceAddr = "" // TODO
	socket.DestAddr = ""   // TODO
}

func (socket *SocketUnknown) ProcessDataEvent(event *events.DataEvent) {

}
