package main

import "C"

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/dockerdog/internal"
	"github.com/evanrolfe/dockerdog/internal/parse"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

const (
	BufPollRateMs = 200
	bpfFilePath   = ".output/tc.bpf.o"
	btfFilePath   = "5.8.0-23-generic.btf"
	interfaceName = "eth0"
	bpfFuncName   = "tc_egress"
)

func formatByteArray(data []byte) string {
	output := ""
	for _, b := range data {
		output += fmt.Sprintf("0x%02x,", b)
	}
	return output
}

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
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()
}

func main() {
	bpfProg, err := internal.NewBPFProgramFromFileArgs(bpfFilePath, btfFilePath, interfaceName, bpfFuncName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfProg.Close()

	// Attach to TC ingress & egress points
	bpfProg.AttachToTC(bpf.BPFTcIngress)
	bpfProg.AttachToTC(bpf.BPFTcEgress)

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
	tcpPayloadsPerfBuf, err := bpfProg.BpfModule.InitRingBuf("tcp_payloads", tcpPayloadsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	tcpPayloadsPerfBuf.Poll(BufPollRateMs)

	packetReceiver := internal.NewPacketReceiver()

	// Setup stream & assembler
	streamFactory := &parse.HttpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	go func() {
		for {
			// Check if the interrupt signal has been received
			select {
			case <-interrupt:
				fmt.Println("Shutting down")
				wg.Done()
				return

			case ipPacketBytes := <-tcpPayloadsChannel:
				// fmt.Println("Received ", len(ipPacket), "bytes")

				// fmt.Println(hex.Dump(ipPacket))
				// fmt.Println(formatByteArray(ipPacketBytes))

				packet := packetReceiver.ReceivePayload(ipPacketBytes)

				if packet.IsComplete() {
					// fmt.Printf("PACKET RECEIVED: %s:%d => %s:%d, TotalLen: %d, raw len: %d\n", packet.SourceAddr(), packet.SourcePort(), packet.DestAddr(), packet.DestPort(), packet.TotalLen(), len(packet.Raw))

					// packet.Debug()
					packet1 := gopacket.NewPacket(packet.Raw, layers.LayerTypeIPv4, gopacket.Default)
					tcp1 := packet1.TransportLayer().(*layers.TCP)
					assembler.AssembleWithTimestamp(packet1.NetworkLayer().NetworkFlow(), tcp1, packet1.Metadata().Timestamp)
				}
			}
		}
	}()

	fmt.Println("Running! Press CTRL+C to exit...")

	// For testing purposes:
	testRequest("http://172.17.0.4")

	wg.Wait()

	assembler.FlushOlderThan(time.Now().Add(-1 * time.Minute))
}
