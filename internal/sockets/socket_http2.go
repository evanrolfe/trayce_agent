package sockets

import (
	"bytes"
	"fmt"
	"sync"

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
	mu          sync.Mutex
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

	socket.LocalAddr = ""  // TODO
	socket.RemoteAddr = "" // TODO

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
	socket.LocalAddr = ""  // TODO
	socket.RemoteAddr = "" // TODO
}

// TODO: Have a structure for handling the frame header + payload?
func (socket *SocketHttp2) ProcessDataEvent(event *events.DataEvent) {
	fmt.Println("\n[SocketHttp2] Received ", event.DataLen, "bytes, source:", event.Source(), ", PID:", event.PID, ", TID:", event.TID, "FD: ", event.FD)
	// utils.PrintBytesHex(event.Payload())

	if socket.SSL && !event.SSL() {
		// If the socket is SSL, then ignore non-SSL events becuase they will just be encrypted gibberish
		return
	}

	if event.SSL() && !socket.SSL {
		fmt.Println("[SocketHttp1.1] upgrading to SSL")
		socket.SSL = true
	}

	// Ignore the http2 magic string (PRI * SM...)
	if len(event.Payload()) >= 24 && bytes.Equal(event.Payload()[0:24], http2MagicString) {
		return
	}

	// Check if the frame is complete, if not buffer it.
	// Its possible we receive partial ingress frame, then an egress frame, then the rest of the ingress frame,
	// so because of that we need to buffer the frame bytes based on ingress/egress direction.
	frameBytes := append(socket.frameBuffer[event.Type()], event.Payload()...)
	frames, remainder := ParseBytesToFrames(frameBytes)

	socket.frameBuffer[event.Type()] = remainder

	for _, frame := range frames {
		socket.processFrame(frame)
	}
}

func (socket *SocketHttp2) processFrame(frame *Http2Frame) {
	stream := socket.findOrCreateStream(frame.StreamID())
	flow := stream.ProcessFrame(frame)
	if flow != nil {
		socket.sendFlowBack(*flow)
	}
}

func (socket *SocketHttp2) findOrCreateStream(streamID uint32) *Http2Stream {
	socket.mu.Lock()
	defer socket.mu.Unlock()

	stream, exists := socket.streams[streamID]
	if !exists {
		fmt.Println("[SocketHTTP2] creating stream", streamID, " socket:", socket.Key())
		stream = NewHttp2Stream()
		socket.streams[streamID] = stream
	}
	fmt.Println("[SocketHTTP2] Found stream", streamID, " socket:", socket.Key())
	return stream
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
