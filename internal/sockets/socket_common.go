package sockets

import (
	"fmt"
)

// SocketCommon implements some common functionality and data used by all socket types
type SocketCommon struct {
	SourceAddr string
	DestAddr   string
	Protocol   string
	PID        uint32
	TID        uint32
	FD         uint32
	SSL        bool

	// If a flow is observed, then these are called
	flowCallbacks []func(Flow)
}

func NewSocketCommonFromUnknown(unkownSocket *SocketUnknown) SocketCommon {
	socket := SocketCommon{
		SourceAddr: unkownSocket.SourceAddr,
		DestAddr:   unkownSocket.DestAddr,
		PID:        unkownSocket.PID,
		TID:        unkownSocket.TID,
		FD:         unkownSocket.FD,
		SSL:        false,
	}

	return socket
}

func (sk *SocketCommon) AddFlowCallback(callback func(Flow)) {
	sk.flowCallbacks = append(sk.flowCallbacks, callback)
}

func (sk *SocketCommon) Key() string {
	return fmt.Sprintf("%s->%s", sk.SourceAddr, sk.DestAddr)
}

func (sk *SocketCommon) UpgradeToSSL() {
	sk.SSL = true
}

// sendFlowBack calls all the callbacks with this flow, unless the flow has a zero address (meaning that we are yet to have received
// a getsockname event which sets the missing source/dest address). In this case it buffers the flow so they can be released
// once the getsockname event is finally received.
func (sk *SocketCommon) sendFlowBack(flow Flow) {
	// blackOnYellow := "\033[30;43m"
	// reset := "\033[0m"

	flow.SourceAddr = sk.SourceAddr
	flow.DestAddr = sk.DestAddr

	// fmt.Printf("%s[Flow]%s Source: %s, Dest: %s, UUID: %s\n", blackOnYellow, reset, flow.SourceAddr, flow.DestAddr, flow.UUID)
	// flow.Debug()

	for _, callback := range sk.flowCallbacks {
		callback(flow)
	}
}
