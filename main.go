package main

import "C"

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/dockerdog/internal"
)

// type TCPHeader struct {
// 	SourcePort      uint16
// 	DestinationPort uint16
// 	SequenceNumber  uint32
// 	AckNumber       uint32
// 	Flags           uint16
// 	Window          uint16
// 	Checksum        uint16
// 	UrgentPointer   uint16
// }

// type UDPHeader struct {
// 	SourcePort      uint16
// 	DestinationPort uint16
// 	Length          uint16
// 	Checksum        uint16
// }

// type SKBuffer struct {
// 	srcAddr   uint32
// 	DestAddr  uint32
// 	UdpHeader UDPHeader
// }

const BufPollRateMs = 200

func testRequest(url string) {
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()
}

func main() {
	bpfModule, err := bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath: ".output/tc.bpf.o",
		BTFObjPath: "5.8.0-23-generic.btf",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// =========================================================================
	// Attach tc_engress
	// =========================================================================
	hook := bpfModule.TcHookInit()
	err = hook.SetInterfaceByName("eth0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to set tc hook on interface eth0: %v", err)
		os.Exit(-1)
	}

	hook.SetAttachPoint(bpf.BPFTcIngress)
	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			fmt.Fprintln(os.Stderr, "tc hook create: %v", err)
		}
	}

	tcProg, err := bpfModule.GetProgram("tc_egress")
	if tcProg == nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	var tcOpts bpf.TcOpts
	tcOpts.ProgFd = int(tcProg.GetFd())
	err = hook.Attach(&tcOpts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// =========================================================================
	// Handle output
	// =========================================================================
	// Create a channel to receive interrupt signals
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	var wg sync.WaitGroup
	// Start a goroutine to handle the interrupt signal
	wg.Add(1)

	// Poll the TCP Payloads perf buffer
	tcpPayloadsChannel := make(chan []byte)
	tcpPayloadsPerfBuf, err := bpfModule.InitRingBuf("tcp_payloads", tcpPayloadsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	tcpPayloadsPerfBuf.Poll(BufPollRateMs)

	packetReceiver := internal.NewPacketReceiver()

	go func() {
		for {
			// Check if the interrupt signal has been received
			select {
			case <-interrupt:
				fmt.Println("Shutting down")
				wg.Done()
				return

			case ipPacket := <-tcpPayloadsChannel:
				fmt.Println("Received ", len(ipPacket), "bytes")

				packet := packetReceiver.ReceivePayload(ipPacket)

				if packet.IsComplete() {
					packet.Debug()
				}
			}
		}
	}()

	fmt.Println("Running! Press CTRL+C to exit...")

	// For testing purposes:
	testRequest("http://172.17.0.4")

	wg.Wait()

	fmt.Println("Dettaching TC program...")
	tcOpts.ProgFd = 0
	tcOpts.ProgId = 0
	tcOpts.Flags = 0
	err = hook.Detach(&tcOpts)
	if tcProg == nil {
		fmt.Fprintln(os.Stderr, "failed to detach hook: %v", err)
		os.Exit(-1)
	}

	err = hook.Destroy()
	if tcProg == nil {
		fmt.Fprintln(os.Stderr, "failed to destroy hook: %v", err)
		os.Exit(-1)
	}
}
