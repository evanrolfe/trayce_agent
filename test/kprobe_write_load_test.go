package test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/dockerdog/api"
	"github.com/evanrolfe/dockerdog/internal"
	"github.com/evanrolfe/dockerdog/internal/bpf_events"
	"github.com/evanrolfe/dockerdog/internal/docker"
	"github.com/evanrolfe/dockerdog/internal/sockets"
	"github.com/evanrolfe/dockerdog/internal/utils"
	"github.com/stretchr/testify/assert"
)

const (
	bpfFilePath = "bundle/ssl.bpf.o"
	btfFilePath = "bundle/6.2.0-26-generic.btf"

	// TODO: Make this value set automatically!!!
	containerId = "5dcb29465ffd"
)

func setupKProbe() (*bpf_events.BPFProgram, chan []byte) {
	// Extract bundled files
	bpfBytes := internal.MustAsset(bpfFilePath)
	btfBytes := internal.MustAsset(btfFilePath)
	btfDestFile := "./5.8.0-23-generic.btf"
	utils.ExtractFile(btfBytes, btfDestFile)
	defer os.Remove(btfDestFile)

	// Start BPF program
	var err error
	bpfProg, err := bpf_events.NewBPFProgramFromBytes(bpfBytes, btfFilePath, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// DataEvents ring buffer
	dataEventsChan := make(chan []byte)
	dataEventsBuf, err := bpfProg.BpfModule.InitRingBuf("data_events", dataEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	dataEventsBuf.Poll(10)

	return bpfProg, dataEventsChan
}

func refreshPids(pidsMap *libbpfgo.BPFMap, containers *docker.Containers) {
	for {
		interceptedPIDs := containers.GetPidsToIntercept()
		// fmt.Println(interceptedPIDs)
		// TODO: Clear all existing intercepted PIDs
		for _, pid := range interceptedPIDs {
			if pidsMap != nil {
				key1 := uint32(pid)
				value1 := uint32(1)
				key1Unsafe := unsafe.Pointer(&key1)
				value1Unsafe := unsafe.Pointer(&value1)
				pidsMap.Update(key1Unsafe, value1Unsafe)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func getEventType(payload []byte) int {
	var eventType uint64
	buf := bytes.NewBuffer(payload)
	if err := binary.Read(buf, binary.LittleEndian, &eventType); err != nil {
		return 0
	}

	return int(eventType)
}

func Test_kprobe_write_load(t *testing.T) {
	// if testing.Short() {
	t.Skip()
	// }

	// Extract bundled files
	bpfBytes := internal.MustAsset(bpfFilePath)
	btfBytes := internal.MustAsset(btfFilePath)
	btfDestFile := "./5.8.0-23-generic.btf"
	libSslPath := "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	utils.ExtractFile(btfBytes, btfDestFile)
	defer os.Remove(btfDestFile)

	flows := []sockets.Flow{}

	// Intercepted PIDs map
	containers := docker.NewContainers("/app/test/scripts/")
	containers.SetSettings(&api.Settings{ContainerIds: []string{containerId}})

	eventStream := bpf_events.NewStream(containers, bpfBytes, btfFilePath, libSslPath)

	// Wait for events to be received within timeout limit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	cmd := exec.Command(requestGoScript, "http://localhost:4122", "1000")
	cmd.Start()

	<-ctx.Done()
	output, _ := cmd.CombinedOutput()
	fmt.Println(output)

	// assert.Equal(t, 2000, len(dataEvents))
	// assert.Equal(t, 2000, len(flows))
	collectedMatches := []int{}

	for _, f := range flows {
		if f.Request == nil {
			continue
		}

		req := string(f.Request[0:8])
		pattern := `GET /(\d+)`
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(req)

		assert.Equal(t, len(matches), 2)
		if len(matches) >= 2 {
			// The number is in the first capture group (index 1)
			number := matches[1]
			n, _ := strconv.Atoi(number)
			collectedMatches = append(collectedMatches, n)
		}
	}

	fmt.Println("Requested paths:\n", collectedMatches)
	for i, n := range collectedMatches {
		assert.Equal(t, i, n)
	}

	eventStream.Close()
}
