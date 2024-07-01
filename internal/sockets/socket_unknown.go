package sockets

import (
	"fmt"

	"github.com/evanrolfe/trayce_agent/internal/events"
)

type SocketUnknown struct {
	LocalAddr  string
	RemoteAddr string
	Protocol   string
	Pid        uint32
	Tid        uint32
	Fd         uint32
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
		LocalAddr:   "unknown",
		Pid:         event.Pid,
		Tid:         event.Tid,
		Fd:          event.Fd,
		SSL:         false,
		requestUuid: "",
	}

	socket.LocalAddr = fmt.Sprintf("%s", event.LocalIPAddr())
	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)

	return socket
}

func (socket *SocketUnknown) Key() string {
	return fmt.Sprintf("%d-%d", socket.Pid, socket.Fd)
}

func (socket *SocketUnknown) Clear() {
}

func (socket *SocketUnknown) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

// ProcessConnectEvent is called when the connect event arrives after the data event
func (socket *SocketUnknown) ProcessConnectEvent(event *events.ConnectEvent) {
	socket.LocalAddr = fmt.Sprintf("%s", event.LocalIPAddr())
	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)
}

// TODO: Make this work with streams
// TODO: Have a structure for handling the frame header + payload
func (socket *SocketUnknown) ProcessDataEvent(event *events.DataEvent) {
	// fmt.Println("[SocketUnknown] ProcessDataEvent, dataBuf len:", len(event.Payload()))

}
