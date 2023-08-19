package internal

import "C"
import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/evanrolfe/dockerdog/internal/models"
)

const (
	bufPollRateMs = 200
	sslLibPath    = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	libcLibPath   = "/usr/lib/x86_64-linux-gnu/libc.so.6"
)

type BPFAgent struct {
	bpfProg              *BPFProgram
	dataEventsChan       chan []byte
	socketAddrEventsChan chan []byte
	debugEventsChan      chan []byte
	interuptChan         chan int
	sockets              models.SocketMap
}

func NewBPFAgent(bpfBytes []byte, btfFilePath string, dockerRootPath string) *BPFAgent {
	bpfProg, err := NewBPFProgramFromBytes(bpfBytes, btfFilePath, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// Intercept the libs from the specified docker container
	sslLibPathDocker := filepath.Join(dockerRootPath, sslLibPath)
	// libcLibPathDocker := filepath.Join(dockerRootPath, libcLibPath)

	// probe_entry_SSL_read
	// Entry gives: HTTP/1.1 301 Moved Permanently..
	bpfProg.AttachToUProbe("probe_entry_SSL_read", "SSL_read", sslLibPathDocker)
	bpfProg.AttachToURetProbe("probe_ret_SSL_read", "SSL_read", sslLibPathDocker)

	// probe_entry_SSL_write
	// Return gives: GET / HTTP/1.1..
	bpfProg.AttachToUProbe("probe_entry_SSL_write", "SSL_write", sslLibPathDocker)
	bpfProg.AttachToURetProbe("probe_ret_SSL_write", "SSL_write", sslLibPathDocker)

	// kprobe connect
	funcName := fmt.Sprintf("__%s_sys_connect", ksymArch())
	bpfProg.AttachToKProbe("probe_connect", funcName)

	// // uprobe_connect
	// bpfProg.AttachToUProbe("probe_connect", "connect", libcLibPathDocker)

	// // uprobe socket
	// bpfProg.AttachToURetProbe("probe_ret_socket", "socket", libcLibPathDocker)

	// // uprobe getsockname
	// bpfProg.AttachToURetProbe("probe_ret_getsockname", "getsockname", libcLibPathDocker)

	// // uprobe send
	// funcName := fmt.Sprintf("__%s_sys_sendto", ksymArch())
	// bpfProg.AttachToKProbe("probe_entry_sendto", funcName)
	// bpfProg.AttachToKRetProbe("probe_ret_send", funcName)

	return &BPFAgent{
		bpfProg:              bpfProg,
		dataEventsChan:       make(chan []byte),
		socketAddrEventsChan: make(chan []byte),
		debugEventsChan:      make(chan []byte),
		interuptChan:         make(chan int),
		sockets:              models.NewSocketMap(),
	}
}

func (agent *BPFAgent) ListenForEvents(outputChan chan models.MsgEvent) {
	// DataEvents ring buffer
	dataEventsBuf, err := agent.bpfProg.BpfModule.InitRingBuf("data_events", agent.dataEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// SocketAddrEvents ring buffer
	socketAddrEventsBuf, err := agent.bpfProg.BpfModule.InitRingBuf("socket_addr_events", agent.socketAddrEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// DebugEvents ring buffer
	debugEventsBuf, err := agent.bpfProg.BpfModule.InitRingBuf("debug_events", agent.debugEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	dataEventsBuf.Poll(bufPollRateMs)
	socketAddrEventsBuf.Poll(bufPollRateMs)
	debugEventsBuf.Poll(bufPollRateMs)

	for {
		// Check if the interrupt signal has been received
		select {
		case <-agent.interuptChan:
			return

		case payload := <-agent.dataEventsChan:
			event := models.DataEvent{}
			event.Decode(payload)
			fmt.Println("[DataEvent] Received ", event.DataLen, "bytes, type:", event.Type(), ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd)

			eventPayload := event.Payload()
			if len(eventPayload) > 256 {
				eventPayload = eventPayload[0:128]
			}
			fmt.Println(hex.Dump(eventPayload))
			// Fetch its corresponding connect event
			socket, exists := agent.sockets[event.Key()]
			if !exists {
				continue
			}
			outputChan <- models.NewMsgEvent(&event, socket)

		case payload := <-agent.socketAddrEventsChan:
			event := models.SocketAddrEvent{}
			event.Decode(payload)
			fmt.Println("[SocketAddrEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port, " local? ", event.Local)

			// Save the event to the map
			agent.sockets.ParseAddrEvent(&event)
		case payload := <-agent.debugEventsChan:
			fmt.Println("[DebugEvent] Received", len(payload), "bytes")
			fmt.Println(hex.Dump(payload))
		}
	}
}

func (agent *BPFAgent) Close() {
	agent.sockets.Debug()
	agent.interuptChan <- 0
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

// -----------------------------------------------------------------------------
// getsockname attempt
// -----------------------------------------------------------------------------

// type SocketAddress struct {
// 	Family uint16
// 	Port   uint16
// 	Addr   uint32
// }
// libcTLS := libc.NewTLS()

// var addrObj SocketAddress
// var addrLenRaw int

// addrPtr := unsafe.Pointer(&addrObj)
// addrLenPtr := unsafe.Pointer(&addrLenRaw)

// _, _, err := unix.Syscall(unix.SYS_GETSOCKNAME, uintptr(event.Fd), uintptr(addrPtr), uintptr(addrLenPtr))
// result := libc.Xgetsockname(libcTLS, int32(event.Fd), uintptr(addrPtr), uintptr(addrLenPtr))

// fmt.Printf("------------------------> addr: %d addrLen: %d, result: %d\n", addrObj, addrLenRaw)

// _, err := C.fn()
// fmt.Println("err:", int(err))
