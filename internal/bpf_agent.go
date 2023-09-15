package internal

import (
	"fmt"

	"github.com/evanrolfe/dockerdog/internal/bpf_events"
	"github.com/evanrolfe/dockerdog/internal/sockets"
)

const (
	bufPollRateMs = 50
)

type BPFAgent struct {
	EventStream *bpf_events.Stream
	sockets     *sockets.SocketMap

	connectCallbacks []func(bpf_events.ConnectEvent)
	dataCallbacks    []func(bpf_events.DataEvent)
	closeCallbacks   []func(bpf_events.CloseEvent)

	eventsChan chan bpf_events.IEvent
}

func NewBPFAgent(bpfBytes []byte, btfFilePath string, libSslPath string) *BPFAgent {
	eventStream := bpf_events.NeStream(bpfBytes, btfFilePath, libSslPath)

	return &BPFAgent{
		EventStream: eventStream,
		sockets:     sockets.NewSocketMap(),
		eventsChan:  make(chan bpf_events.IEvent),
	}
}

func (agent *BPFAgent) RegisterConnectEventCallback(event string, callback func(bpf_events.ConnectEvent)) {
	agent.connectCallbacks = append(agent.connectCallbacks, callback)
}

func (agent *BPFAgent) RegisterDataEventCallback(event string, callback func(bpf_events.DataEvent)) {
	agent.dataCallbacks = append(agent.dataCallbacks, callback)
}

func (agent *BPFAgent) RegisterCloseEventCallback(event string, callback func(bpf_events.CloseEvent)) {
	agent.closeCallbacks = append(agent.closeCallbacks, callback)
}

func (agent *BPFAgent) ListenForEvents(outputChan chan sockets.Flow) {
	// eventChan := make(chan bpf_events.IEvent)
	agent.EventStream.Start(agent.eventsChan)

	for {
		select {
		case event := <-agent.eventsChan:
			fmt.Println("Got an event!", event.Key())
		}
	}
	// for {
	// 	// Check if the interrupt signal has been received
	// 	select {
	// 	// case <-agent.interuptChan:
	// 	// 	return

	// 	case payload := <-agent.connectEventsChan:
	// 		event := bpf_events.ConnectEvent{}
	// 		event.Decode(payload)
	// 		fmt.Println("[ConnectEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port, " local? ", event.Local)

	// 		agent.sockets.ProcessConnectEvent(&event)

	// 	case payload := <-agent.dataEventsChan:
	// 		event := bpf_events.DataEvent{}
	// 		event.Decode(payload)

	// 		if event.DataLen != 104 {
	// 			fmt.Println("[DataEvent] Received ", event.DataLen, "bytes, type:", event.DataType, ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd)
	// 			fmt.Println(hex.Dump(event.Payload()))
	// 		}

	// 		flow, _ := agent.sockets.ProcessDataEvent(&event)

	// 		if err != nil {
	// 			fmt.Println("NO SOCKET FOUND")
	// 		}

	// 		if flow != nil {
	// 			outputChan <- *flow
	// 		}

	// 	case payload := <-agent.closeEventsChan:
	// 		event := bpf_events.CloseEvent{}
	// 		event.Decode(payload)

	// 		// agent.sockets.ProcessCloseEvent(&event)

	// 	case _ = <-agent.debugEventsChan:
	// 		continue
	// 		// fmt.Println("[DebugEvent] Received", len(payload), "bytes")
	// 		// fmt.Println(hex.Dump(payload))
	// 	}
	// }
}

func (agent *BPFAgent) Close() {
	agent.EventStream.Close()
}
