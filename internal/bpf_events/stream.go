package bpf_events

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/dockerdog/internal/docker"
)

const (
	bufPollRateMs              = 50
	containerPIDsRefreshRateMs = 5
)

type Stream struct {
	bpfProg         *BPFProgram
	containers      *docker.Containers
	interceptedPIDs []int

	dataEventsBuf  *libbpfgo.RingBuffer
	pidsMap        *libbpfgo.BPFMap
	dataEventsChan chan []byte
	interruptChan  chan int

	connectCallbacks []func(ConnectEvent)
	dataCallbacks    []func(DataEvent)
	closeCallbacks   []func(CloseEvent)
}

func NewStream(containers *docker.Containers, bpfBytes []byte, btfFilePath string, libSslPath string) *Stream {
	bpfProg, err := NewBPFProgramFromBytes(bpfBytes, btfFilePath, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// uprobe/SSL_read
	bpfProg.AttachToUProbe("probe_entry_SSL_read", "SSL_read", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_read", "SSL_read", libSslPath)

	// uprobe/SSL_read_ex
	bpfProg.AttachToUProbe("probe_entry_SSL_read_ex", "SSL_read_ex", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_read_ex", "SSL_read_ex", libSslPath)

	// uprobe/SSL_write
	bpfProg.AttachToUProbe("probe_entry_SSL_write", "SSL_write", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_write", "SSL_write", libSslPath)

	// uprobe/SSL_write_ex
	bpfProg.AttachToUProbe("probe_entry_SSL_write_ex", "SSL_write_ex", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_write_ex", "SSL_write_ex", libSslPath)

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

	// kprobe write
	funcName = fmt.Sprintf("__%s_sys_write", ksymArch())
	bpfProg.AttachToKProbe("probe_write", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_write", funcName)

	// kprobe read
	funcName = fmt.Sprintf("__%s_sys_read", ksymArch())
	bpfProg.AttachToKProbe("probe_read", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_read", funcName)

	// kprobe security_socket_sendmsg
	bpfProg.AttachToKProbe("probe_entry_security_socket_sendmsg", "security_socket_sendmsg")

	// kprobe security_socket_recvmsg
	bpfProg.AttachToKProbe("probe_entry_security_socket_recvmsg", "security_socket_recvmsg")

	return &Stream{
		bpfProg:         bpfProg,
		containers:      containers,
		interceptedPIDs: []int{},
		interruptChan:   make(chan int),
		dataEventsChan:  make(chan []byte),
	}
}

func (stream *Stream) AddConnectCallback(callback func(ConnectEvent)) {
	stream.connectCallbacks = append(stream.connectCallbacks, callback)
}

func (stream *Stream) AddDataCallback(callback func(DataEvent)) {
	stream.dataCallbacks = append(stream.dataCallbacks, callback)
}

func (stream *Stream) AddCloseCallback(callback func(CloseEvent)) {
	stream.closeCallbacks = append(stream.closeCallbacks, callback)
}

func (stream *Stream) Start(outputChan chan IEvent) {
	// DataEvents ring buffer
	var err error
	stream.dataEventsBuf, err = stream.bpfProg.BpfModule.InitRingBuf("data_events", stream.dataEventsChan)
	if err != nil {
		panic(err)
	}
	stream.dataEventsBuf.Poll(bufPollRateMs)

	// Intercepted PIDs map
	pidsMap, err := stream.bpfProg.BpfModule.GetMap("intercepted_pids")
	if err != nil {
		panic(err)
	}
	stream.pidsMap = pidsMap
	go stream.refreshPids()

	for {
		// Check if the interrupt signal has been received
		select {
		case <-stream.interruptChan:
			return

		case payload := <-stream.dataEventsChan:
			eventType := getEventType(payload)

			// ConnectEvent
			if eventType == 0 {
				event := ConnectEvent{}
				event.Decode(payload)

				// if event.Fd < 10 {
				// 	fmt.Println("[ConnectEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port, " local? ", event.Local)
				// }
				fmt.Println("\n[ConnectEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port, " local? ", event.Local)
				outputChan <- &event

				// DataEvent
			} else if eventType == 1 {
				event := DataEvent{}
				event.Decode(payload)
				if event.IsBlank() {
					continue
				}
				fmt.Println("\n[DataEvent] Received ", event.DataLen, "bytes, source:", event.Source(), ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, " rand:", event.Rand)
				fmt.Print(hex.Dump(event.PayloadTrimmed(256)))

				outputChan <- &event

				// DebugEvent
			} else if eventType == 3 {
				event := DebugEvent{}
				event.Decode(payload)
				fmt.Println("\n[DebugEvent] Received, PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, " - ", string(event.Payload()))
				// fmt.Print(hex.Dump(payload))
			}
		}
	}
}

func (stream *Stream) Close() {
	stream.interruptChan <- 1
	stream.bpfProg.Close()
}

func (stream *Stream) refreshPids() {
	for {
		stream.interceptedPIDs = stream.containers.GetPidsToIntercept()

		// TODO: Clear all existing intercepted PIDs
		for _, pid := range stream.interceptedPIDs {
			if stream.pidsMap != nil {
				key1 := uint32(pid)
				value1 := uint32(1)
				key1Unsafe := unsafe.Pointer(&key1)
				value1Unsafe := unsafe.Pointer(&value1)
				stream.pidsMap.Update(key1Unsafe, value1Unsafe)
			}
		}
		time.Sleep(containerPIDsRefreshRateMs * time.Millisecond)
	}
}

func ksymArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		panic("unsupported architecture")
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
