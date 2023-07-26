package main

import "C"
import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/evanrolfe/dockerdog/internal"
)

const (
	BufPollRateMs = 200
	bpfFilePath   = ".output/ssl.bpf.o"
	btfFilePath   = "5.8.0-23-generic.btf"
	interfaceName = "eth0"
	bpfFuncName   = "tc_egress"
	sslLibPath    = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	libcLibPath   = "/usr/lib/x86_64-linux-gnu/libc.so.6"
)

func main() {
	msgEventsChan := make(chan internal.MsgEvent)
	agent := internal.NewBPFAgent(bpfFilePath, btfFilePath)
	defer agent.Close()

	// Create a channel to receive interrupt signals
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	fmt.Println("Agent listing...")
	go agent.ListenForEvents(msgEventsChan)

	// Start a goroutine to handle the interrupt signal
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		for {
			// Check if the interrupt signal has been received
			select {
			case <-interrupt:
				wg.Done()
				return
			case msgEvent := <-msgEventsChan:
				fmt.Println(hex.Dump(msgEvent.Payload))
			}
		}
	}()

	// For testing purposes:
	cmd := exec.Command("curl", "http://www.pntest.io", "--http1.1")
	cmd.Output()

	wg.Wait()

	fmt.Println("Done, closing agent.")
}

// func main() {
// 	_, err := os.Stat(sslLibPath)
// 	if err != nil {
// 		fmt.Fprintln(os.Stderr, err)
// 		os.Exit(-1)
// 	}

// 	bpfProg, err := internal.NewBPFProgramFromFileArgs(bpfFilePath, btfFilePath, interfaceName)
// 	if err != nil {
// 		fmt.Fprintln(os.Stderr, err)
// 		os.Exit(-1)
// 	}
// 	defer bpfProg.Close()

// 	// probe_entry_SSL_read
// 	// Entry gives: HTTP/1.1 301 Moved Permanently..
// 	bpfProg.AttachToUProbe("probe_entry_SSL_read", "SSL_read", sslLibPath)
// 	bpfProg.AttachToURetProbe("probe_ret_SSL_read", "SSL_read", sslLibPath)

// 	// probe_entry_SSL_write
// 	// Return gives: GET / HTTP/1.1..
// 	bpfProg.AttachToUProbe("probe_entry_SSL_write", "SSL_write", sslLibPath)
// 	bpfProg.AttachToURetProbe("probe_ret_SSL_write", "SSL_write", sslLibPath)

// 	// probe_connect
// 	bpfProg.AttachToUProbe("probe_connect", "connect", libcLibPath)
// 	// bpfProg.AttachToURetProbe("probe_ret_connect", "connect", libcLibPath)

// 	// urp
// 	bpfProg.AttachToUProbe("probe_entry_send", "send", libcLibPath)
// 	bpfProg.AttachToURetProbe("probe_ret_send", "send", libcLibPath)
// 	// bpfProg.AttachToKProbe("probe_entry_send", "__x64_sys_send")
// 	// bpfProg.AttachToKProbe("probe_ret_send", "__x64_sys_send")

// 	// Channel
// 	// Create a channel to receive interrupt signals
// 	interrupt := make(chan os.Signal, 1)
// 	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
// 	var wg sync.WaitGroup
// 	// Start a goroutine to handle the interrupt signal
// 	wg.Add(1)

// 	// // Create a channel to receive events from the ebpf program
// 	tlsEventsChannel := make(chan []byte)
// 	connectEventsChannel := make(chan []byte)
// 	// lostChannel := make(chan uint64)
// 	tlsEventsBuf, err := bpfProg.BpfModule.InitRingBuf("tls_events", tlsEventsChannel)
// 	if err != nil {
// 		fmt.Fprintln(os.Stderr, err)
// 		os.Exit(-1)
// 	}
// 	connectEventsBuf, err := bpfProg.BpfModule.InitRingBuf("connect_events", connectEventsChannel)
// 	if err != nil {
// 		fmt.Fprintln(os.Stderr, err)
// 		os.Exit(-1)
// 	}

// 	tlsEventsBuf.Poll(BufPollRateMs)
// 	connectEventsBuf.Poll(BufPollRateMs)

// 	go func() {
// 		for {
// 			// Check if the interrupt signal has been received
// 			select {
// 			case <-interrupt:
// 				fmt.Println("Shutting down")
// 				wg.Done()
// 				return

// 			case payload := <-tlsEventsChannel:
// 				event := internal.SSLDataEvent{}
// 				event.Decode(payload)
// 				fmt.Println("[TLSEvent] Received ", event.DataLen, "bytes, type:", event.Type(), ", PID:", event.Pid, ", TID:", event.Tid)

// 				// fmt.Println(event.GetUUID())
// 				fmt.Println(hex.Dump(event.Data[0:event.DataLen]))

// 			case payload := <-connectEventsChannel:
// 				fmt.Println("[ConnectEvent] Received ", len(payload), "bytes")
// 				event := internal.ConnDataEvent{}
// 				event.Decode(payload)
// 				// err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &event)
// 				// if err != nil {
// 				// 	fmt.Println("Error parsing payload:", err)
// 				// 	return
// 				// }

// 				fmt.Println("Received ", len(payload), " bytes (ConnectEvet)")
// 				// fmt.Println(hex.Dump(payload))
// 				// fmt.Println(event.StringHex())
// 				fmt.Println("PID:", event.Pid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port)
// 			}

// 		}
// 	}()

// 	fmt.Println("Running! Press CTRL+C to exit...")

// 	// For testing purposes:
// 	cmd := exec.Command("curl", "http://www.pntest.io", "--http1.1")
// 	cmd.Output()

// 	wg.Wait()

// 	// rb.Close()
// }
