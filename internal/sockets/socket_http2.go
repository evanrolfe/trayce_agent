package sockets

import (
	"bytes"
	"fmt"

	"github.com/evanrolfe/trayce_agent/internal/events"
)

type SocketHttp2 struct {
	LocalAddr  string
	RemoteAddr string
	Protocol   string
	PID        uint32
	TID        uint32
	FD         uint32
	SSL        bool

	streams     map[uint32]*Http2Stream
	frameBuffer map[string][]byte

	// If a flow is observed, then these are called
	flowCallbacks []func(Flow)
}

func NewSocketHttp2(event *events.ConnectEvent) SocketHttp2 {
	socket := SocketHttp2{
		LocalAddr:   "unknown",
		PID:         event.PID,
		TID:         event.TID,
		FD:          event.FD,
		SSL:         false,
		streams:     map[uint32]*Http2Stream{},
		frameBuffer: map[string][]byte{},
	}

	socket.frameBuffer[events.TypeIngress] = []byte{}
	socket.frameBuffer[events.TypeEgress] = []byte{}

	socket.LocalAddr = fmt.Sprintf("%s", event.LocalIPAddr())
	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)

	return socket
}

func NewSocketHttp2FromUnknown(unkownSocket *SocketUnknown) SocketHttp2 {
	socket := SocketHttp2{
		LocalAddr:   unkownSocket.LocalAddr,
		RemoteAddr:  unkownSocket.RemoteAddr,
		PID:         unkownSocket.PID,
		TID:         unkownSocket.TID,
		FD:          unkownSocket.FD,
		SSL:         false,
		streams:     map[uint32]*Http2Stream{},
		frameBuffer: map[string][]byte{},
	}

	socket.frameBuffer[events.TypeIngress] = []byte{}
	socket.frameBuffer[events.TypeEgress] = []byte{}

	return socket
}

func (socket *SocketHttp2) Key() string {
	return fmt.Sprintf("%d-%d", socket.PID, socket.FD)
}

func (socket *SocketHttp2) Clear() {
	socket.clearFrameBuffer(events.TypeIngress)
	socket.clearFrameBuffer(events.TypeEgress)
}

func (socket *SocketHttp2) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

// ProcessConnectEvent is called when the connect event arrives after the data event
func (socket *SocketHttp2) ProcessConnectEvent(event *events.ConnectEvent) {
	socket.LocalAddr = fmt.Sprintf("%s", event.LocalIPAddr())
	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)
}

// TODO: Have a structure for handling the frame header + payload?
func (socket *SocketHttp2) ProcessDataEvent(event *events.DataEvent) {
	// fmt.Println("\n[SocketHttp2] Received ", event.DataLen, "bytes, source:", event.Source(), ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, " ssl_ptr:", event.SslPtr, "\n", hex.Dump(event.Payload()))
	// utils.PrintBytesHex(event.Payload())

	// Ignore the http2 magic string (PRI * SM...)
	if len(event.Payload()) >= 24 && bytes.Equal(event.Payload()[0:24], http2MagicString) {
		return
	}

	// Check if the frame is complete, if not buffer it.
	// Its possible we receive partial ingress frame, then an egress frame, then the rest of the ingress frame,
	// so because of that we need to buffer the frame bytes based on ingress/egress direction.
	frameBytes := append(socket.frameBuffer[event.Type()], event.Payload()...)
	frame := NewHttp2Frame(frameBytes)

	if !frame.Complete() {
		socket.frameBuffer[event.Type()] = frameBytes
		return
	}

	// fmt.Println("[SocketHttp2] complete frame received, type: ", frame.Type(), " length:", frame.Length(), " stream:", frame.StreamID())
	// fmt.Println(frame.Payload())

	// We have a complete frame so can clear the buffer now
	socket.clearFrameBuffer(event.Type())

	stream := socket.findOrCreateStream(frame.StreamID())

	flow := stream.ProcessFrame(frame)
	if flow != nil {
		socket.sendFlowBack(*flow)
	}
}

func (socket *SocketHttp2) findOrCreateStream(streamID uint32) *Http2Stream {
	stream, _ := socket.streams[streamID]
	if stream == nil {
		stream = NewHttp2Stream()
		socket.setStream(streamID, stream)
	}
	return stream
}

func (socket *SocketHttp2) setStream(streamID uint32, stream *Http2Stream) {
	socket.streams[streamID] = stream
}

func (socket *SocketHttp2) clearFrameBuffer(key string) {
	socket.frameBuffer[key] = []byte{}
}

func (socket *SocketHttp2) sendFlowBack(flow Flow) {
	blackOnYellow := "\033[30;43m"
	reset := "\033[0m"
	fmt.Printf("%s[Flow]%s Local: %s, Remote: %s, UUID: %s\n", blackOnYellow, reset, flow.LocalAddr, flow.RemoteAddr, flow.UUID)
	flow.Debug()

	for _, callback := range socket.flowCallbacks {
		callback(flow)
	}
}
