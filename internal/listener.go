package internal

import (
	"github.com/evanrolfe/dockerdog/internal/bpf_events"
	"github.com/evanrolfe/dockerdog/internal/sockets"
)

type Listener struct {
	EventStream *bpf_events.Stream
	sockets     *sockets.SocketMap
}

func NewListener(bpfBytes []byte, btfFilePath string, libSslPath string) *Listener {
	eventStream := bpf_events.NewStream(bpfBytes, btfFilePath, libSslPath)

	return &Listener{
		EventStream: eventStream,
		sockets:     sockets.NewSocketMap(),
	}
}

func (listener *Listener) Start(outputChan chan sockets.Flow) {
	listener.EventStream.AddConnectCallback(listener.sockets.ProcessConnectEvent)
	listener.EventStream.AddDataCallback(listener.sockets.ProcessDataEvent)
	listener.EventStream.AddCloseCallback(listener.sockets.ProcessCloseEvent)

	listener.sockets.AddFlowCallback(func(flow sockets.Flow) { outputChan <- flow })

	listener.EventStream.Start()
}

func (listener *Listener) Close() {
	listener.EventStream.Close()
}
