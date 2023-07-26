package internal

import (
	"encoding/hex"
	"fmt"
	"os"
)

const (
	BufPollRateMs = 200
	sslLibPath    = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	libcLibPath   = "/usr/lib/x86_64-linux-gnu/libc.so.6"
)

type BPFAgent struct {
	bpfProg        *BPFProgram
	tlsEventsChan  chan []byte
	connEventsChan chan []byte
	interuptChan   chan int
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

	// probe_connect
	bpfProg.AttachToUProbe("probe_connect", "connect", libcLibPath)

	// uprobe send
	bpfProg.AttachToUProbe("probe_entry_send", "send", libcLibPath)
	bpfProg.AttachToURetProbe("probe_ret_send", "send", libcLibPath)

	return &BPFAgent{
		bpfProg:        bpfProg,
		tlsEventsChan:  make(chan []byte),
		connEventsChan: make(chan []byte),
		interuptChan:   make(chan int),
	}
}

func (agent *BPFAgent) ListenForEvents(outputChan chan MsgEvent) {
	tlsEventsBuf, err := agent.bpfProg.BpfModule.InitRingBuf("tls_events", agent.tlsEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	connEventsBuf, err := agent.bpfProg.BpfModule.InitRingBuf("connect_events", agent.connEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	tlsEventsBuf.Poll(BufPollRateMs)
	connEventsBuf.Poll(BufPollRateMs)

	for {
		// Check if the interrupt signal has been received
		select {
		case <-agent.interuptChan:
			return

		case payload := <-agent.tlsEventsChan:
			event := SSLDataEvent{}
			event.Decode(payload)
			fmt.Println("[TLSEvent] Received ", event.DataLen, "bytes, type:", event.Type(), ", PID:", event.Pid, ", TID:", event.Tid)

			// fmt.Println(event.GetUUID())
			fmt.Println(hex.Dump(event.Data[0:event.DataLen]))

			// msgEvent := MsgEvent{Payload: event.Data[0:event.DataLen]}
			// outputChan <- msgEvent

		case payload := <-agent.connEventsChan:
			fmt.Println("[ConnectEvent] Received ", len(payload), "bytes")
			event := ConnDataEvent{}
			event.Decode(payload)
			// err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &event)
			// if err != nil {
			// 	fmt.Println("Error parsing payload:", err)
			// 	return
			// }

			// fmt.Println("Received ", len(payload), " bytes (ConnectEvet)")
			// fmt.Println(hex.Dump(payload))
			// fmt.Println(event.StringHex())
			fmt.Println("PID:", event.Pid, "TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port)
		}
	}
}

func (agent *BPFAgent) Close() {
	agent.interuptChan <- 0
	// close(agent.connEventsChan)
	// close(agent.tlsEventsChan)
	agent.bpfProg.Close()
}
