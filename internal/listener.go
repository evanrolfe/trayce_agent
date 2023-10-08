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

func NewListener(bpfBytes []byte, btfFilePath string, libSslPath string, filterCmd string) *Listener {
	containers := docker.NewContainers(filterCmd)

	return &Listener{
		containers:  containers,
		eventStream: bpf_events.NewStream(containers, bpfBytes, btfFilePath, libSslPath),
		sockets:     sockets.NewSocketMap(),
	}
}

func (listener *Listener) Start(outputChan chan sockets.Flow) {
	// TODO: Would probably be better to do this with an interface and accept the SocketsMap as a dependency injection
	// rather than with callbacks

	// TODO: Just let this send flows directly to the channel
	listener.sockets.AddFlowCallback(func(flow sockets.Flow) { outputChan <- flow })

	eventsChan := make(chan bpf_events.IEvent)
	go listener.eventStream.Start(eventsChan)

	for {
		event := <-eventsChan

		switch ev := event.(type) {
		case *bpf_events.ConnectEvent:
			listener.sockets.ProcessConnectEvent(*ev)
		case *bpf_events.DataEvent:
			listener.sockets.ProcessDataEvent(*ev)
		case *bpf_events.CloseEvent:
			listener.sockets.ProcessCloseEvent(*ev)
		default:
			panic("Listener.Start() event has to be ConnectEvent, DataEvent or CloseEvent")
		}
	}
}

func (listener *Listener) SetSettings(settings *api.Settings) {
	listener.containers.SetSettings(settings)
}

func (listener *Listener) Close() {
	listener.eventStream.Close()
}
