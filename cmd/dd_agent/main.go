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
	"github.com/evanrolfe/dockerdog/internal/models"
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
	msgEventsChan := make(chan models.MsgEvent)
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
				fmt.Printf("[MsgEvent] Local: %s, Remote: %s\n", msgEvent.LocalAddr, msgEvent.RemoteAddr)
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
