package bpf_events

import (
	"fmt"
	"os"
	"runtime"

	"github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/dockerdog/internal/docker"
)

const (
	bufPollRateMs = 50
)

type Stream struct {
	bpfProg *BPFProgram

	dataEventsBuf    *libbpfgo.RingBuffer
	connectEventsBuf *libbpfgo.RingBuffer
	closeEventsBuf   *libbpfgo.RingBuffer
	debugEventsBuf   *libbpfgo.RingBuffer

	dataEventsChan    chan []byte
	connectEventsChan chan []byte
	closeEventsChan   chan []byte
	debugEventsChan   chan []byte
	interruptChan     chan int

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

	// uprobe SSL_read
	bpfProg.AttachToUProbe("probe_entry_SSL_read", "SSL_read", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_read", "SSL_read", libSslPath)

	// uprobe SSL_read_ex
	bpfProg.AttachToUProbe("probe_entry_SSL_read_ex", "SSL_read_ex", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_read_ex", "SSL_read_ex", libSslPath)

	// uprobe SSL_write
	bpfProg.AttachToUProbe("probe_entry_SSL_write", "SSL_write", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_write", "SSL_write", libSslPath)

	// uprobe SSL_write_ex
	bpfProg.AttachToUProbe("probe_entry_SSL_write_ex", "SSL_write_ex", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_write_ex", "SSL_write_ex", libSslPath)

	// kprobe connect
	funcName := fmt.Sprintf("__%s_sys_connect", ksymArch())
	bpfProg.AttachToKProbe("probe_connect", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_connect", funcName)

	// kprobe close
	funcName = fmt.Sprintf("__%s_sys_close", ksymArch())
	bpfProg.AttachToKProbe("probe_close", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_close", funcName)

	// kprobe sendto
	funcName = fmt.Sprintf("__%s_sys_sendto", ksymArch())
	bpfProg.AttachToKProbe("probe_sendto", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_sendto", funcName)

	// kprobe recvfrom
	funcName = fmt.Sprintf("__%s_sys_recvfrom", ksymArch())
	bpfProg.AttachToKProbe("probe_recvfrom", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_recvfrom", funcName)

	// // kprobe write
	// funcName = fmt.Sprintf("__%s_sys_write", ksymArch())
	// bpfProg.AttachToKProbe("probe_write", funcName)
	// bpfProg.AttachToKRetProbe("probe_ret_write", funcName)

	// // kprobe read
	// funcName = fmt.Sprintf("__%s_sys_read", ksymArch())
	// bpfProg.AttachToKProbe("probe_read", funcName)
	// bpfProg.AttachToKRetProbe("probe_ret_read", funcName)

	// kprobe security_socket_sendmsg
	// bpfProg.AttachToKProbe("probe_entry_security_socket_sendmsg", "security_socket_sendmsg")

	// kprobe security_socket_recvmsg
	// bpfProg.AttachToKProbe("probe_entry_security_socket_recvmsg", "security_socket_recvmsg")

	return &Stream{
		bpfProg:       bpfProg,
		interruptChan: make(chan int),

		dataEventsChan:    make(chan []byte),
		connectEventsChan: make(chan []byte),
		closeEventsChan:   make(chan []byte),
		debugEventsChan:   make(chan []byte),
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

func (stream *Stream) Start() {
	// DataEvents ring buffer
	var err error
	stream.dataEventsBuf, err = stream.bpfProg.BpfModule.InitRingBuf("data_events", stream.dataEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// ConnectEvents ring buffer
	stream.connectEventsBuf, err = stream.bpfProg.BpfModule.InitRingBuf("connect_events", stream.connectEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// CloseEvents ring buffer
	stream.closeEventsBuf, err = stream.bpfProg.BpfModule.InitRingBuf("close_events", stream.closeEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// DebugEvents ring buffer
	stream.debugEventsBuf, err = stream.bpfProg.BpfModule.InitRingBuf("debug_events", stream.debugEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	stream.dataEventsBuf.Poll(bufPollRateMs)
	stream.connectEventsBuf.Poll(bufPollRateMs)
	stream.closeEventsBuf.Poll(bufPollRateMs)
	stream.debugEventsBuf.Poll(bufPollRateMs)

	for {
		// Check if the interrupt signal has been received
		select {
		case <-stream.interruptChan:
			return

		case payload := <-stream.connectEventsChan:
			event := ConnectEvent{}
			event.Decode(payload)
			// if event.Fd < 10 {
			// 	fmt.Println("[ConnectEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port, " local? ", event.Local)
			// }
			for _, callback := range stream.connectCallbacks {
				callback(event)
			}
		case payload := <-stream.dataEventsChan:
			event := DataEvent{}
			event.Decode(payload)
			// if event.Fd < 10 {
			// 	fmt.Println("[DataEvent] Received ", event.DataLen, "bytes, type:", event.DataType, ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd)
			// 	fmt.Println(hex.Dump(event.Payload()))
			// }
			for _, callback := range stream.dataCallbacks {
				callback(event)
			}

		case payload := <-stream.closeEventsChan:
			event := CloseEvent{}
			event.Decode(payload)
			// if event.Fd < 10 && event.Fd > 0 {
			// 	fmt.Println("[CloseEvent] Received, PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd)
			// }
			for _, callback := range stream.closeCallbacks {
				callback(event)
			}
		case _ = <-stream.debugEventsChan:
			continue
			// fmt.Println("[DebugEvent] Received", len(payload), "bytes")
			// fmt.Println(hex.Dump(payload))
		}
	}
}

func (stream *Stream) Close() {
	stream.interruptChan <- 1
	stream.bpfProg.Close()
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
