package test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/evanrolfe/dockerdog/api"
	"github.com/evanrolfe/dockerdog/internal"
	"github.com/evanrolfe/dockerdog/internal/bpf_events"
	"github.com/evanrolfe/dockerdog/internal/docker"
	"github.com/evanrolfe/dockerdog/internal/sockets"
	"github.com/evanrolfe/dockerdog/internal/utils"
	"github.com/stretchr/testify/assert"
)

func Test_kprobe_write2(t *testing.T) {
	// if testing.Short() {
	// t.Skip()
	// }
	// Extract bundled files
	bpfBytes := internal.MustAsset(bpfFilePath)
	btfBytes := internal.MustAsset(btfFilePath)
	btfDestFile := "./5.8.0-23-generic.btf"
	libSslPath := "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	utils.ExtractFile(btfBytes, btfDestFile)
	defer os.Remove(btfDestFile)

	var bpfProg *bpf_events.BPFProgram
	flows := []sockets.Flow{}

	// Intercepted PIDs map
	containers := docker.NewContainers("/app/test/scripts/")
	containers.SetSettings(&api.Settings{ContainerIds: []string{containerId}})

	eventStream := bpf_events.NewStream(containers, bpfBytes, btfFilePath, libSslPath)

	// Wait for events to be received within timeout limit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start listening for events async
	eventsChan := make(chan bpf_events.IEvent)
	go eventStream.Start(eventsChan)

	socketMap := sockets.NewSocketMap()
	socketMap.AddFlowCallback(func(f sockets.Flow) {
		flows = append(flows, f)
	})

	go func() {
		for {
			event := <-eventsChan

			switch ev := event.(type) {
			case *bpf_events.ConnectEvent:
				socketMap.ProcessConnectEvent(*ev)
			case *bpf_events.DataEvent:
				socketMap.ProcessDataEvent(*ev)
			case *bpf_events.CloseEvent:
				socketMap.ProcessCloseEvent(*ev)
			default:
				panic("Listener.Start() event has to be ConnectEvent, DataEvent or CloseEvent")
			}
		}
	}()

	// Make an HTTP request which should trigger the event from kprobe/sendto
	cmd := exec.Command(requestGoScript, "http://localhost:4122/", "10000")
	cmd.Start()

	<-ctx.Done()
	output, _ := cmd.CombinedOutput()
	fmt.Println(output)

	// assert.Equal(t, 2000, len(dataEvents))
	assert.Equal(t, 20000, len(flows))

	bpfProg.Close()
}
