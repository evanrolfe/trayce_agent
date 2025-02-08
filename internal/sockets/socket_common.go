package sockets

import (
	"fmt"
	"strings"
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
	// The flows are buffered until a GetsocknameEvent is received which sets the source/dest address on the flows
	flowBuf []Flow
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

func (socket *SocketCommon) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

func (socket *SocketCommon) Key() string {
	return fmt.Sprintf("%s->%s", socket.SourceAddr, socket.DestAddr)
}

func (socket *SocketCommon) GetPID() uint32 {
	return socket.PID
}

func (socket *SocketCommon) SetPID(pid uint32) {
	socket.PID = pid
}

func (socket *SocketCommon) Clone() SocketCommon {
	return SocketCommon{
		SourceAddr: socket.SourceAddr,
		DestAddr:   socket.DestAddr,
		PID:        socket.PID,
		TID:        socket.TID,
		FD:         socket.FD,
		SSL:        socket.SSL,
	}
}

// releaseFlows releases the flows which have been buffered
func (socket *SocketCommon) releaseFlows() {
	for _, flow := range socket.flowBuf {
		socket.sendFlowBack(flow, true)
	}

	socket.flowBuf = []Flow{}
}

// sendFlowBack calls all the callbacks with this flow, unless the flow has a zero address (meaning that we are yet to have received
// a getsockname event which sets the missing source/dest address). In this case it buffers the flow so they can be released
// once the getsockname event is finally received.
func (socket *SocketCommon) sendFlowBack(flow Flow, bufferOnZeroPort bool) {
	blackOnYellow := "\033[30;43m"
	reset := "\033[0m"

	// dont check the source port because it causes issues with python requests and we dont really care about the source port anwyay
	// also dont check mysql sockets cause they never send a getsockname event at all so we just accept the port will always be 0 for mysql
	if socket.hasZeroPortDest() && bufferOnZeroPort {
		fmt.Printf("%s[Flow]%s buffered UUID: %s\n", blackOnYellow, reset, flow.UUID)
		socket.flowBuf = append(socket.flowBuf, flow)
		return
	}

	flow.SourceAddr = socket.SourceAddr
	flow.DestAddr = socket.DestAddr

	fmt.Printf("%s[Flow]%s Source: %s, Dest: %s, UUID: %s\n", blackOnYellow, reset, flow.SourceAddr, flow.DestAddr, flow.UUID)
	flow.Debug()

	for _, callback := range socket.flowCallbacks {
		callback(flow)
	}
}

// hasZeroPortSource returns true if the destination address has a zero port
func (socket *SocketCommon) hasZeroPortSource() bool {
	sourceAddrSplit := strings.Split(socket.SourceAddr, ":")
	sourcePort := sourceAddrSplit[1]

	return sourcePort == "0"
}

// hasZeroPortDest returns true if the source address has a zero port
func (socket *SocketCommon) hasZeroPortDest() bool {
	destAddrSplit := strings.Split(socket.DestAddr, ":")
	destPort := destAddrSplit[1]

	return destPort == "0"
}
