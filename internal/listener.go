package internal

import (
	"github.com/evanrolfe/dockerdog/api"
	"github.com/evanrolfe/dockerdog/internal/bpf_events"
	"github.com/evanrolfe/dockerdog/internal/docker"
	"github.com/evanrolfe/dockerdog/internal/sockets"
)

type Listener struct {
	containers  *docker.Containers
	eventStream *bpf_events.Stream
	sockets     *sockets.SocketMap
}

func NewListener(bpfBytes []byte, btfFilePath string, libSslPath string) *Listener {
	containers := docker.NewContainers()

	return &Listener{
		containers:  containers,
		eventStream: bpf_events.NewStream(containers, bpfBytes, btfFilePath, libSslPath),
		sockets:     sockets.NewSocketMap(),
	}
}

func (listener *Listener) Start(outputChan chan sockets.Flow) {
	// TODO: Would probably be better to do this with an interface and accept the SocketsMap as a dependency injection
	// rather than with callbacks
	listener.eventStream.AddConnectCallback(listener.sockets.ProcessConnectEvent)
	listener.eventStream.AddDataCallback(listener.sockets.ProcessDataEvent)
	listener.eventStream.AddCloseCallback(listener.sockets.ProcessCloseEvent)

	listener.sockets.AddFlowCallback(func(flow sockets.Flow) { outputChan <- flow })

	listener.eventStream.Start()
}

func (listener *Listener) SetSettings(settings *api.Settings) {
	listener.containers.SetSettings(settings)
}

func (listener *Listener) Close() {
	listener.eventStream.Close()
}
