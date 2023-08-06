package internal

import "C"
import (
	"fmt"
	"os"

	"github.com/evanrolfe/dockerdog/internal/models"
)

const (
	BufPollRateMs = 200
	sslLibPath    = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	libcLibPath   = "/usr/lib/x86_64-linux-gnu/libc.so.6"
)

type BPFAgent struct {
	bpfProg              *BPFProgram
	dataEventsChan       chan []byte
	socketAddrEventsChan chan []byte
	interuptChan         chan int
	sockets              models.SocketMap
}

func NewBPFAgent(bpfFilePath string, btfFilePath string) *BPFAgent {
	bpfProg, err := NewBPFProgramFromFileArgs(bpfFilePath, btfFilePath, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// probe_entry_SSL_read
	// Entry gives: HTTP/1.1 301 Moved Permanently..
	bpfProg.AttachToUProbe("probe_entry_SSL_read", "SSL_read", sslLibPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_read", "SSL_read", sslLibPath)

	// probe_entry_SSL_write
	// Return gives: GET / HTTP/1.1..
	bpfProg.AttachToUProbe("probe_entry_SSL_write", "SSL_write", sslLibPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_write", "SSL_write", sslLibPath)

	// uprobe_connect
	bpfProg.AttachToUProbe("probe_connect", "connect", libcLibPath)

	// uprobe socket
	bpfProg.AttachToURetProbe("probe_ret_socket", "socket", libcLibPath)

	// uprobe getsockname
	bpfProg.AttachToURetProbe("probe_ret_getsockname", "getsockname", libcLibPath)

	// uprobe send
	bpfProg.AttachToUProbe("probe_entry_send", "send", libcLibPath)
	bpfProg.AttachToURetProbe("probe_ret_send", "send", libcLibPath)

	return &BPFAgent{
		bpfProg:              bpfProg,
		dataEventsChan:       make(chan []byte),
		socketAddrEventsChan: make(chan []byte),
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

	dataEventsBuf.Poll(BufPollRateMs)
	socketAddrEventsBuf.Poll(BufPollRateMs)

	for {
		// Check if the interrupt signal has been received
		select {
		case <-agent.interuptChan:
			return

		case payload := <-agent.dataEventsChan:
			event := models.DataEvent{}
			event.Decode(payload)
			fmt.Println("[DataEvent] Received ", event.DataLen, "bytes, type:", event.Type(), ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd)

			// Fetch its corresponding connect event
			socket, exists := agent.sockets[event.Key()]
			if !exists {
				continue
			}
			outputChan <- models.NewMsgEvent(&event, socket)

		case payload := <-agent.socketAddrEventsChan:
			event := models.SocketAddrEvent{}
			event.Decode(payload)
			if event.Local {
				fmt.Println("[SocketAddrEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port, " local? ", event.Local)
			}

			// Save the event to the map
			agent.sockets.ParseAddrEvent(&event)
		}
	}
}

func (agent *BPFAgent) Close() {
	agent.sockets.Debug()
	agent.interuptChan <- 0
	agent.bpfProg.Close()
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
