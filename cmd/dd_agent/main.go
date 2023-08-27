package main

import "C"
import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/evanrolfe/dockerdog/internal"
	"github.com/evanrolfe/dockerdog/internal/bpf_events"
)

const (
	bpfFilePath   = "bundle/ssl.bpf.o"
	btfFilePath   = "bundle/6.2.0-26-generic.btf"
	sslLibDefault = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
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
	// Parse Command line args
	var pid int
	var libSslPath string
	flag.IntVar(&pid, "pid", 0, "The PID of the docker container to instrument. Or 0 to intsrument this container.")
	flag.StringVar(&libSslPath, "libssl", sslLibDefault, "The path to the libssl shared object.")
	flag.Parse()

	fmt.Println("PID: ", pid)
	fmt.Println("libssl: ", libSslPath)

	// Extract bundled files
	bpfBytes := internal.MustAsset(bpfFilePath)
	btfBytes := internal.MustAsset(btfFilePath)
	btfDestFile := "./5.8.0-23-generic.btf"
	extractFile(btfBytes, btfDestFile)

	// Start the agent
	agent := internal.NewBPFAgent(bpfBytes, btfFilePath, libSslPath)
	defer agent.Close()

	// Create a channel to receive interrupt signals
	interrupt := make(chan os.Signal, 1)
	msgEventsChan := make(chan bpf_events.MsgEvent)
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
				fmt.Printf("[MsgEvent] %s - Local: %s, Remote: %s\n", msgEvent.Type, msgEvent.LocalAddr, msgEvent.RemoteAddr)
				fmt.Println(hex.Dump(msgEvent.Payload))

				for _, b := range msgEvent.Payload {
					fmt.Printf(`\x%02x`, b)
				}
				fmt.Printf("\n")
			}
		}
	}()

	// For testing purposes:
	// cmd := exec.Command("curl", "--parallel", "--parallel-immediate", "--config", "/app/urls.txt", "--http1.1")
	// cmd.Output()
	cmd := exec.Command("ruby", "tmp/request.rb")
	cmd.Output()

	wg.Wait()

	fmt.Println("Done, closing agent.")
	os.Remove(btfDestFile)

	// agent.Close()
}
