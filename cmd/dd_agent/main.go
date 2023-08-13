package main

import "C"
import (
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
	bpfFilePath = ".output/ssl.bpf.o"
	btfFilePath = "5.8.0-23-generic.btf"
)

func main() {
	args := os.Args
	dockerRootPath := ""

	if len(args) == 2 {
		dockerPid := args[1]
		dockerRootPath = fmt.Sprintf("/proc/%s/root", dockerPid)
	} else if len(args) > 2 {
		fmt.Println("Wrong args. Example: ./dd_agents {PID}")
		return
	}

	msgEventsChan := make(chan models.MsgEvent)
	agent := internal.NewBPFAgent(bpfFilePath, btfFilePath, dockerRootPath)
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
				// fmt.Println(hex.Dump(msgEvent.Payload))
			}
		}
	}()

	// For testing purposes:
	cmd := exec.Command("curl", "https://www.pntest.io", "--http1.1")
	cmd.Output()

	wg.Wait()

	fmt.Println("Done, closing agent.")
}
