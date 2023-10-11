package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/evanrolfe/dockerdog/internal"
)

const (
	bpfFilePath = "bundle/ssl.bpf.o"
	btfFilePath = "bundle/6.2.0-26-generic.btf"
	binPath     = "/app/go_request"
)

func extractFile(data []byte, destPath string) {
	f, err := os.Create(destPath)
	if err != nil {
		panic(err)
	}

	_, err = f.Write(data)
	if err != nil {
		panic(err)
	}

	f.Close()
}

func main() {
	// value := 420
	// bytes := make([]byte, 4) // Assuming int is 8 bytes on a 64-bit system

	// binary.LittleEndian.PutUint32(bytes, uint32(value))
	// fmt.Printf(hex.Dump(bytes))
	// return
	// Extract bundled files
	bpfBytes := internal.MustAsset(bpfFilePath)
	btfBytes := internal.MustAsset(btfFilePath)
	btfDestFile := "./5.8.0-23-generic.btf"
	extractFile(btfBytes, btfDestFile)
	defer os.Remove(btfDestFile)

	bpfProg, err := internal.NewBPFProgramFromBytes(bpfBytes, btfFilePath, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// probe_entry_SSL_read
	// Entry gives: HTTP/1.1 301 Moved Permanently..
	bpfProg.AttachToUProbe("probe_entry_go", "main.makeRequest", binPath)
	// bpfProg.AttachToURetProbe("probe_ret_go", "main.makeRequest", binPath)

	// Create a channel to receive interrupt signals
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)

	// DebugEvents ring buffer
	debugEventsChan := make(chan []byte)
	debugEventsBuf, err := bpfProg.BpfModule.InitRingBuf("debug_events", debugEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	debugEventsBuf.Poll(200)
	fmt.Println("started")

	for {
		// Check if the interrupt signal has been received
		select {
		case <-interruptChan:
			fmt.Println("exiting")
			return

		case payload := <-debugEventsChan:
			fmt.Println("[DebugEvent] Received", len(payload), "bytes")
			fmt.Println(hex.Dump(payload))
		}
	}
}
