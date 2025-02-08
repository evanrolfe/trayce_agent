package internal

import (
	"fmt"
	"os"

	"github.com/evanrolfe/trayce_agent/internal/docker"
	"github.com/evanrolfe/trayce_agent/internal/ebpf"
	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/evanrolfe/trayce_agent/internal/sockets"
)

type Listener struct {
	containers  *docker.Containers
	eventStream *ebpf.Stream
	sockets     *sockets.SocketMap
}

func NewListener(bpfBytes []byte, btfFilePath string, libSslPath string, filterCmd string) *Listener {
	containers := docker.NewContainers(filterCmd)

	// TODO: libSslPath is unused
	bpfProg, err := ebpf.NewProbeManagerFromBytes(bpfBytes, btfFilePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	return &Listener{
		containers:  containers,
		eventStream: ebpf.NewStream(containers, bpfProg),
		sockets:     sockets.NewSocketMap(),
	}
}

func (listener *Listener) Start(outputChan chan sockets.Flow) {
	// TODO: Just let this send flows directly to the channel
	listener.sockets.AddFlowCallback(func(flow sockets.Flow) { outputChan <- flow })

	eventsChan := make(chan events.IEvent, 1000)
	go listener.eventStream.Start(eventsChan)

	for {
		event := <-eventsChan
		switch ev := event.(type) {
		case *events.DataEvent:
			listener.sockets.ProcessDataEvent(*ev)
		case *events.CloseEvent:
			listener.sockets.ProcessCloseEvent(*ev)
		default:
			fmt.Println("ERROR: Listener.Start() event type not handled")
		}
	}
}

func (listener *Listener) SetContainers(containerIds []string) {
	listener.containers.SetContainers(containerIds)
}

// GetAllContainers returns all containers running on the machine
func (listener *Listener) GetAllContainers() ([]docker.ContainerGUI, error) {
	return listener.containers.GetAllContainers()
}

func (listener *Listener) Close() {
	listener.eventStream.Close()
}
