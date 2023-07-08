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

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
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

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap("events")
	if err != nil {
		return err
	}

	if err = m.Resize(size); err != nil {
		return err
	}

	if actual := m.GetMaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}

	return nil
}

func main() {
	_, err := os.Stat(sslLibPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfModule, err := bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath: bpfFilePath,
		BTFObjPath: btfFilePath,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()
	bpfModule.BPFLoadObject()

	// ------------------------------------------------------------------------
	// probe_entry_SSL_read
	// ------------------------------------------------------------------------
	prog, err := bpfModule.GetProgram("probe_entry_SSL_read")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	offset, err := helpers.SymbolToOffset(sslLibPath, "SSL_read")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog.AttachUprobe(-1, sslLibPath, offset)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	// ------------------------------------------------------------------------
	// probe_entry_SSL_read
	// ------------------------------------------------------------------------
	prog2, err := bpfModule.GetProgram("probe_ret_SSL_read")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog2.AttachURetprobe(-1, sslLibPath, offset)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// ------------------------------------------------------------------------
	// probe_entry_SSL_write
	// ------------------------------------------------------------------------
	prog3, err := bpfModule.GetProgram("probe_entry_SSL_write")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	offset3, err := helpers.SymbolToOffset(sslLibPath, "SSL_write")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog3.AttachUprobe(-1, sslLibPath, offset3)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	// ------------------------------------------------------------------------
	// probe_entry_SSL_write
	// ------------------------------------------------------------------------
	prog4, err := bpfModule.GetProgram("probe_ret_SSL_write")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog4.AttachURetprobe(-1, sslLibPath, offset3)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

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
	rb, err := bpfModule.InitRingBuf("tls_events", eventsChannel)
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
				fmt.Println("Received ", len(payload), "bytes")
				event := internal.SSLDataEvent{}
				event.Decode(payload)

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
