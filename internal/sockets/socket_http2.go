package sockets

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/evanrolfe/trayce_agent/internal/bpf_events"
)

type SocketHttp2 struct {
	LocalAddr  string
	RemoteAddr string
	Protocol   string
	Pid        uint32
	Tid        uint32
	Fd         uint32
	SSL        bool

	streams     map[uint32]*Http2Stream
	frameBuffer map[string][]byte

	// If a flow is observed, then these are called
	flowCallbacks []func(Flow)
	// When a request is observed, this value is set, when the response comes, we send this value back with the response
	requestUuid string
}

func NewSocketHttp2(event *bpf_events.ConnectEvent) SocketHttp2 {
	socket := SocketHttp2{
		LocalAddr:   "unknown",
		Pid:         event.Pid,
		Tid:         event.Tid,
		Fd:          event.Fd,
		SSL:         false,
		requestUuid: "",
		streams:     map[uint32]*Http2Stream{},
		frameBuffer: map[string][]byte{},
	}

	socket.frameBuffer[bpf_events.TypeIngress] = []byte{}
	socket.frameBuffer[bpf_events.TypeEgress] = []byte{}

	socket.LocalAddr = fmt.Sprintf("%s", event.LocalIPAddr())
	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)

	return socket
}

func NewSocketHttp2FromUnknown(unkownSocket *SocketUnknown) SocketHttp2 {
	socket := SocketHttp2{
		LocalAddr:   unkownSocket.LocalAddr,
		RemoteAddr:  unkownSocket.RemoteAddr,
		Pid:         unkownSocket.Pid,
		Tid:         unkownSocket.Tid,
		Fd:          unkownSocket.Fd,
		SSL:         false,
		requestUuid: "",
		streams:     map[uint32]*Http2Stream{},
		frameBuffer: map[string][]byte{},
	}

	socket.frameBuffer[bpf_events.TypeIngress] = []byte{}
	socket.frameBuffer[bpf_events.TypeEgress] = []byte{}

	return socket
}

func (socket *SocketHttp2) Key() string {
	return fmt.Sprintf("%d-%d", socket.Pid, socket.Fd)
}

func (socket *SocketHttp2) Clear() {
	socket.clearFrameBuffer(bpf_events.TypeIngress)
	socket.clearFrameBuffer(bpf_events.TypeEgress)
}

func (socket *SocketHttp2) AddFlowCallback(callback func(Flow)) {
	socket.flowCallbacks = append(socket.flowCallbacks, callback)
}

// ProcessConnectEvent is called when the connect event arrives after the data event
func (socket *SocketHttp2) ProcessConnectEvent(event *bpf_events.ConnectEvent) {
	socket.LocalAddr = fmt.Sprintf("%s", event.LocalIPAddr())
	socket.RemoteAddr = fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)
}

// TODO: Have a structure for handling the frame header + payload?
func (socket *SocketHttp2) ProcessDataEvent(event *bpf_events.DataEvent) {
	fmt.Println("\n[SocketHttp2] Received ", event.DataLen, "bytes, source:", event.Source(), ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, " ssl_ptr:", event.SslPtr)
	fmt.Print(hex.Dump(event.PayloadTrimmed(256)))
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
		fmt.Println("[SocketHttp2] incomplete frame")
		socket.frameBuffer[event.Type()] = frameBytes
		return
	}

	// fmt.Println("[SocketHttp2] frame received, type: ", frame.Type(), " length:", frame.Length(), " stream:", frame.StreamID())
	// fmt.Print(hex.Dump(frame.raw))

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
	fmt.Printf("[Flow] %s - Local: %s, Remote: %s, UUID: %s\n", "", flow.LocalAddr, flow.RemoteAddr, flow.UUID)
	flow.Debug()

	for _, callback := range socket.flowCallbacks {
		callback(flow)
	}
}
