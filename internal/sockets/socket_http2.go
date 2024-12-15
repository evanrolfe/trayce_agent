package sockets

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/evanrolfe/trayce_agent/internal/events"
)

type SocketHttp2 struct {
	SourceAddr string
	DestAddr   string
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
	// The flows are buffered until a GetsocknameEvent is received which sets the source/dest address on the flows
	flowBuf []Flow
}

func NewSocketHttp2(event *events.ConnectEvent) SocketHttp2 {
	socket := SocketHttp2{
		SourceAddr:  event.SourceAddr(),
		DestAddr:    event.DestAddr(),
		PID:         event.PID,
		TID:         event.TID,
		FD:          event.FD,
		SSL:         false,
		streams:     map[uint32]*Http2Stream{},
		frameBuffer: map[string][]byte{},
		flowBuf:     []Flow{},
	}
	socket.frameBuffer[events.TypeIngress] = []byte{}
	socket.frameBuffer[events.TypeEgress] = []byte{}

	return socket
}

func NewSocketHttp2FromUnknown(unkownSocket *SocketUnknown) SocketHttp2 {
	socket := SocketHttp2{
		SourceAddr:  unkownSocket.SourceAddr,
		DestAddr:    unkownSocket.DestAddr,
		PID:         unkownSocket.PID,
		TID:         unkownSocket.TID,
		FD:          unkownSocket.FD,
		SSL:         false,
		streams:     map[uint32]*Http2Stream{},
		frameBuffer: map[string][]byte{},
		flowBuf:     []Flow{},
	}
	socket.frameBuffer[events.TypeIngress] = []byte{}
	socket.frameBuffer[events.TypeEgress] = []byte{}

	return socket
}

func (socket *SocketHttp2) Key() string {
	return fmt.Sprintf("%d-%d", socket.PID, socket.FD)
}

func (socket *SocketHttp2) GetPID() uint32 {
	return socket.PID
}

func (socket *SocketHttp2) SetPID(pid uint32) {
	socket.PID = pid
}

func (socket *SocketHttp2) Clone() SocketI {
	return &SocketHttp2{
		SourceAddr:  socket.SourceAddr,
		DestAddr:    socket.DestAddr,
		PID:         socket.PID,
		TID:         socket.TID,
		FD:          socket.FD,
		SSL:         socket.SSL,
		streams:     map[uint32]*Http2Stream{},
		frameBuffer: map[string][]byte{},
		flowBuf:     []Flow{},
	}
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
}

func (socket *SocketHttp2) ProcessGetsocknameEvent(event *events.GetsocknameEvent) {
	sourceAddrSplit := strings.Split(socket.SourceAddr, ":")
	sourcePort := sourceAddrSplit[1]

	destAddrSplit := strings.Split(socket.DestAddr, ":")
	destPort := destAddrSplit[1]

	if sourcePort == "0" {
		socket.SourceAddr = event.Addr()
	} else if destPort == "0" {
		socket.DestAddr = event.Addr()
	}

	socket.releaseFlows()
}

// TODO: Have a structure for handling the frame header + payload?
func (socket *SocketHttp2) ProcessDataEvent(event *events.DataEvent) {
	socket.mu.Lock()
	defer socket.mu.Unlock()

	fmt.Println("\n[SocketHttp2] Received ", event.DataLen, "bytes, source:", event.Source(), ", PID:", event.PID, ", TID:", event.TID, "FD: ", event.FD)
	// fmt.Println(hex.Dump(event.Payload()))

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

func (socket *SocketHttp2) releaseFlows() {
	for _, flow := range socket.flowBuf {
		flow.SourceAddr = socket.SourceAddr
		flow.DestAddr = socket.DestAddr
		socket.sendFlowBack(flow)
	}

	socket.flowBuf = []Flow{}
}

func (socket *SocketHttp2) sendFlowBack(flow Flow) {
	blackOnYellow := "\033[30;43m"
	reset := "\033[0m"

	if socket.DestAddr == ZeroAddr || socket.SourceAddr == ZeroAddr {
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
