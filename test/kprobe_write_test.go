package test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
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

const containerId = "5dcb29465ffd"

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

func Test_kprobe_write(t *testing.T) {
	// if testing.Short() {
	// t.Skip()
	// }

	var bpfProg *bpf_events.BPFProgram
	dataEvents := []bpf_events.DataEvent{}
	flows := []sockets.Flow{}

	bpfProg2, dataEventsChan := setupKProbe()
	bpfProg = bpfProg2

	// kprobe/connect
	funcName := fmt.Sprintf("__%s_sys_connect", ksymArch())
	bpfProg.AttachToKProbe("probe_connect", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_connect", funcName)

	// kprobe/close
	funcName = fmt.Sprintf("__%s_sys_close", ksymArch())
	bpfProg.AttachToKProbe("probe_close", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_close", funcName)

	// kprobe/sendto
	funcName = fmt.Sprintf("__%s_sys_sendto", ksymArch())
	bpfProg.AttachToKProbe("probe_sendto", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_sendto", funcName)

	// kprobe/recvfrom
	funcName = fmt.Sprintf("__%s_sys_recvfrom", ksymArch())
	bpfProg.AttachToKProbe("probe_recvfrom", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_recvfrom", funcName)

	// Attach kprobe/write
	funcName = fmt.Sprintf("__%s_sys_write", ksymArch())
	bpfProg.AttachToKProbe("probe_write", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_write", funcName)

	// Attach kprobe/read
	funcName = fmt.Sprintf("__%s_sys_read", ksymArch())
	bpfProg.AttachToKProbe("probe_read", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_read", funcName)

	// kprobe security_socket_sendmsg
	bpfProg.AttachToKProbe("probe_entry_security_socket_sendmsg", "security_socket_sendmsg")

	// kprobe security_socket_recvmsg
	bpfProg.AttachToKProbe("probe_entry_security_socket_recvmsg", "security_socket_recvmsg")

	// Intercepted PIDs map
	containers := docker.NewContainers("/app/test/scripts/")
	containers.SetSettings(&api.Settings{ContainerIds: []string{containerId}})

	pidsMap, err := bpfProg.BpfModule.GetMap("intercepted_pids")
	if err != nil {
		panic(err)
	}
	go refreshPids(pidsMap, containers)

	// Wait for events to be received within timeout limit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start listening for events async
	eventsChan := make(chan bpf_events.IEvent)

	go func() {
		for {
			// Check if the interrupt signal has been received
			select {
			case <-ctx.Done():
				return

			case payload := <-dataEventsChan:
				eventType := getEventType(payload)

				// ConnectEvent
				if eventType == 0 {
					event := bpf_events.ConnectEvent{}
					event.Decode(payload)
					fmt.Println("\n[ConnectEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port, " local? ", event.Local)
					eventsChan <- &event
					// DataEvent
				} else if eventType == 1 {
					event := bpf_events.DataEvent{}
					event.Decode(payload)
					if event.IsBlank() {
						continue
					}

					fmt.Println("\n[DataEvent] Received ", event.DataLen, "bytes, source:", event.Source(), ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, " rand:", event.Rand)
					fmt.Print(hex.Dump(event.PayloadTrimmed(128)))

					dataEvents = append(dataEvents, event)
					eventsChan <- &event

					// DebugEvent
				} else if eventType == 3 {
					event := bpf_events.DebugEvent{}
					event.Decode(payload)
					fmt.Println("\n[DebugEvent] Received, PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, " - ", string(event.Payload()))
				}
			}
		}
	}()

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
	cmd := exec.Command(requestGoScript, "http://localhost:4122/", "1000")
	cmd.Start()

	<-ctx.Done()
	output, _ := cmd.CombinedOutput()
	fmt.Println(output)

	// assert.Equal(t, 2000, len(dataEvents))
	assert.Equal(t, 2000, len(flows))

	bpfProg.Close()
}
