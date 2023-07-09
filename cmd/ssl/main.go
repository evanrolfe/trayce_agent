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
)

func main() {
	_, err := os.Stat(sslLibPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfProg, err := internal.NewBPFProgramFromFileArgs(bpfFilePath, btfFilePath, interfaceName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfProg.Close()

	// ------------------------------------------------------------------------
	// probe_entry_SSL_read
	// Entry gives: HTTP/1.1 301 Moved Permanently..
	// ------------------------------------------------------------------------
	bpfProg.AttachToUProbe("probe_entry_SSL_read", "SSL_read", sslLibPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_read", "SSL_read", sslLibPath)

	// ------------------------------------------------------------------------
	// probe_entry_SSL_write
	// Return gives: GET / HTTP/1.1..
	// ------------------------------------------------------------------------
	bpfProg.AttachToUProbe("probe_entry_SSL_write", "SSL_write", sslLibPath)
	bpfProg.AttachToURetProbe("probe_ret_SSL_write", "SSL_write", sslLibPath)

	// ------------------------------------------------------------------------
	// Channel
	// ------------------------------------------------------------------------
	// Create a channel to receive interrupt signals
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	var wg sync.WaitGroup
	// Start a goroutine to handle the interrupt signal
	wg.Add(1)

	// // Create a channel to receive events from the ebpf program
	eventsChannel := make(chan []byte)
	// lostChannel := make(chan uint64)
	rb, err := bpfProg.BpfModule.InitRingBuf("tls_events", eventsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.Poll(BufPollRateMs)

	go func() {
		for {
			// Check if the interrupt signal has been received
			select {
			case <-interrupt:
				fmt.Println("Shutting down")
				wg.Done()
				return

			case payload := <-eventsChannel:
				event := internal.SSLDataEvent{}
				event.Decode(payload)
				fmt.Println("Received ", event.DataLen, "bytes, type:", event.Type())

				fmt.Println(event.GetUUID())
				fmt.Println(hex.Dump(event.Data[0:event.DataLen]))
			}
		}
	}()

	fmt.Println("Running! Press CTRL+C to exit...")

	// For testing purposes:
	cmd := exec.Command("curl", "https://www.pntest.io", "--http1.1")
	cmd.Output()

	wg.Wait()

	// rb.Close()
}
