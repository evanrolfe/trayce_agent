package internal

import "C"
import (
	"fmt"
	"os"
	"runtime"

	"github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/dockerdog/internal/bpf_events"
	"github.com/evanrolfe/dockerdog/internal/sockets"
)

const (
	bufPollRateMs = 50
)

type BPFAgent struct {
	bpfProg           *BPFProgram
	sockets           sockets.SocketMap
	interuptChan      chan int
	dataEventsChan    chan []byte
	connectEventsChan chan []byte
	closeEventsChan   chan []byte
	debugEventsChan   chan []byte
	dataEventsBuf     *libbpfgo.RingBuffer
	connectEventsBuf  *libbpfgo.RingBuffer
	closeEventsBuf    *libbpfgo.RingBuffer
	debugEventsBuf    *libbpfgo.RingBuffer
}

func NewBPFAgent(bpfBytes []byte, btfFilePath string, libSslPath string) *BPFAgent {
	bpfProg, err := NewBPFProgramFromBytes(bpfBytes, btfFilePath, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// probe_entry_SSL_read
	// Entry gives: HTTP/1.1 301 Moved Permanently..
	bpfProg.AttachToUProbe("probe_entry_SSL_read", "SSL_read", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_read", "SSL_read", libSslPath)

	bpfProg.AttachToUProbe("probe_entry_SSL_read_ex", "SSL_read_ex", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_read_ex", "SSL_read_ex", libSslPath)

	// probe_entry_SSL_write
	// Return gives: GET / HTTP/1.1..
	bpfProg.AttachToUProbe("probe_entry_SSL_write", "SSL_write", libSslPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_write", "SSL_write", libSslPath)

	// kprobe connect
	funcName := fmt.Sprintf("__%s_sys_connect", ksymArch())
	bpfProg.AttachToKProbe("probe_connect", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_connect", funcName)

	// kprobe close
	funcName = fmt.Sprintf("__%s_sys_close", ksymArch())
	bpfProg.AttachToKProbe("probe_close", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_close", funcName)

	return &BPFAgent{
		bpfProg:           bpfProg,
		sockets:           sockets.NewSocketMap(),
		interuptChan:      make(chan int),
		dataEventsChan:    make(chan []byte),
		connectEventsChan: make(chan []byte),
		closeEventsChan:   make(chan []byte),
		debugEventsChan:   make(chan []byte),
	}
}

func (agent *BPFAgent) ListenForEvents(outputChan chan sockets.SocketMsg) {
	// DataEvents ring buffer
	var err error
	agent.dataEventsBuf, err = agent.bpfProg.BpfModule.InitRingBuf("data_events", agent.dataEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// ConnectEvents ring buffer
	agent.connectEventsBuf, err = agent.bpfProg.BpfModule.InitRingBuf("connect_events", agent.connectEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// CloseEvents ring buffer
	agent.closeEventsBuf, err = agent.bpfProg.BpfModule.InitRingBuf("close_events", agent.closeEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// DebugEvents ring buffer
	agent.debugEventsBuf, err = agent.bpfProg.BpfModule.InitRingBuf("debug_events", agent.debugEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	agent.dataEventsBuf.Poll(bufPollRateMs)
	agent.connectEventsBuf.Poll(bufPollRateMs)
	agent.closeEventsBuf.Poll(bufPollRateMs)
	agent.debugEventsBuf.Poll(bufPollRateMs)

	for {
		// Check if the interrupt signal has been received
		select {
		case <-agent.interuptChan:
			return

		case payload := <-agent.connectEventsChan:
			event := bpf_events.ConnectEvent{}
			event.Decode(payload)
			// fmt.Println("[ConnectEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port, " local? ", event.Local)

			agent.sockets.ProcessConnectEvent(&event)

		case payload := <-agent.dataEventsChan:
			event := bpf_events.DataEvent{}
			event.Decode(payload)
			// fmt.Println("[DataEvent] Received ", event.DataLen, "bytes, type:", event.Type(), ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd)

			msg, err := agent.sockets.ProcessDataEvent(&event)
			if err != nil {
				fmt.Println("NO SOCKET FOUND")
			}

			if msg != nil {
				msg.Debug()
				outputChan <- *msg
			}

		case payload := <-agent.closeEventsChan:
			event := bpf_events.CloseEvent{}
			event.Decode(payload)

			// agent.sockets.ProcessCloseEvent(&event)

		case _ = <-agent.debugEventsChan:
			continue
			// fmt.Println("[DebugEvent] Received", len(payload), "bytes")
			// fmt.Println(hex.Dump(payload))
		}
	}
}

func (agent *BPFAgent) Close() {
	agent.interuptChan <- 1
	agent.bpfProg.Close()
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
