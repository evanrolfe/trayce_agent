package sockets

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/evanrolfe/trayce_agent/internal/events"
)

type SocketHttp2 struct {
	Common SocketCommon

	streams     map[uint32]*Http2Stream
	frameBuffer map[string][]byte
	mu          sync.Mutex
}

func NewSocketHttp2(sourceAddr, destAddr string, pid, tid, fd uint32) SocketHttp2 {
	socket := SocketHttp2{
		Common: SocketCommon{
			SourceAddr: sourceAddr,
			DestAddr:   destAddr,
			PID:        pid,
			TID:        tid,
			FD:         fd,
			SSL:        false,
		},
		streams:     map[uint32]*Http2Stream{},
		frameBuffer: map[string][]byte{},
	}
	socket.frameBuffer[events.TypeIngress] = []byte{}
	socket.frameBuffer[events.TypeEgress] = []byte{}

	return socket
}

func NewSocketHttp2FromUnknown(unkownSocket *SocketUnknown) SocketHttp2 {
	socket := SocketHttp2{
		Common: SocketCommon{
			SourceAddr: unkownSocket.SourceAddr,
			DestAddr:   unkownSocket.DestAddr,
			PID:        unkownSocket.PID,
			TID:        unkownSocket.TID,
			FD:         unkownSocket.FD,
			SSL:        false,
		},
		streams:     map[uint32]*Http2Stream{},
		frameBuffer: map[string][]byte{},
	}
	socket.frameBuffer[events.TypeIngress] = []byte{}
	socket.frameBuffer[events.TypeEgress] = []byte{}

	return socket
}

func (socket *SocketHttp2) Key() string {
	return socket.Common.Key()
}

func (socket *SocketHttp2) AddFlowCallback(callback func(Flow)) {
	socket.Common.AddFlowCallback(callback)
}

// TODO: Have a structure for handling the frame header + payload?
func (socket *SocketHttp2) ProcessDataEvent(event *events.DataEvent) {
	socket.mu.Lock()
	defer socket.mu.Unlock()

	fmt.Println("\n[SocketHttp2] Received ", event.DataLen, "bytes, source:", event.Source(), ", PID:", event.PID, ", TID:", event.TID, "FD: ", event.FD)
	// fmt.Println(hex.Dump(event.Payload()))

	if socket.Common.SSL && !event.SSL() {
		// If the socket is SSL, then ignore non-SSL events becuase they will just be encrypted gibberish
		return
	}

	if event.SSL() && !socket.Common.SSL {
		fmt.Println("[SocketHttp1.1] upgrading to SSL")
		socket.Common.SSL = true
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
		socket.Common.sendFlowBack(*flow)
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
