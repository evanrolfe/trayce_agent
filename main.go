package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/miekg/dns"

	bpf "github.com/aquasecurity/libbpfgo"
)

type UDPHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
}

type SKBuffer struct {
	srcAddr   uint32
	DestAddr  uint32
	UdpHeader UDPHeader
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

	hook := bpfModule.TcHookInit()
	err = hook.SetInterfaceByName("eth0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to set tc hook on interface eth0: %v", err)
		os.Exit(-1)
	}

	hook.SetAttachPoint(bpf.BPFTcEgress)
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

	// Create a channel to receive interrupt signals
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	var wg sync.WaitGroup
	// Start a goroutine to handle the interrupt signal
	wg.Add(1)

	// Poll the perf buffer
	udpHeadersChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	udpHeadersPerfBuf, err := bpfModule.InitPerfBuf("udp_payloads", udpHeadersChannel, lostChannel, 1)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	udpHeadersPerfBuf.Poll(300)

	go func() {
		for {
			// Check if the interrupt signal has been received
			select {
			case <-interrupt:
				fmt.Println("Shutting down")
				wg.Done()
				return
			case eventBytes := <-udpHeadersChannel:
				fmt.Println("-------------------------------------------------")
				fmt.Println("Bytes: ", eventBytes)
				var udpHeader UDPHeader

				// Parse the UDP header from bytes
				fmt.Println("Sizeof UDPHeader: ", binary.Size(UDPHeader{}))
				udpHeaderBytes := eventBytes[0:8]
				payloadBytes := eventBytes[8:]
				fmt.Println("udpHeaderBytes: ", udpHeaderBytes)
				fmt.Println("payloadBytes:")
				fmt.Println(hex.Dump(eventBytes))

				err = binary.Read(bytes.NewReader(udpHeaderBytes), binary.BigEndian, &udpHeader)
				if err != nil {
					fmt.Println("Failed to parse UDP header:", err)
					return
				}

				// Print the parsed UDP header fields
				fmt.Println("Source Port:", udpHeader.SourcePort)
				fmt.Println("Destination Port:", udpHeader.DestinationPort)
				fmt.Println("Length:", udpHeader.Length)
				fmt.Println("Checksum:", udpHeader.Checksum)

				// Create a new dnsmessage
				msg := new(dns.Msg)

				// Parse the byte array into the dnsmessage
				err := msg.Unpack(payloadBytes)
				if err != nil {
					fmt.Println("Error unpacking DNS message:", err)
					return
				}
				fmt.Println("\nDNS Message:")
				fmt.Println("OpCode:", msg.Opcode)
				fmt.Println("Q Name:", msg.Question[0].Name)
				fmt.Println("Q Class:", msg.Question[0].Qclass)
				fmt.Println("Q Type:", msg.Question[0].Qtype)

			}
		}
	}()

	fmt.Println("Running! Press CTRL+C to exit...")
	wg.Wait()

	// Get BPF Maps
	// udpPayloadsMap, err := bpfModule.GetMap("udp_payloads")
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, err)
	// 	os.Exit(-1)
	// }
	// udpIndexMap, err := bpfModule.GetMap("udp_packets_index")
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, err)
	// 	os.Exit(-1)
	// }

	// var key uint32 = 0
	// udpIndex, err := udpIndexMap.GetValue(unsafe.Pointer(&key))
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, err)
	// }

	// udpIndexInt := binary.LittleEndian.Uint32(udpIndex)

	// fmt.Println("---> udpIndexMap ValueSize: ", udpIndexMap.ValueSize())
	// fmt.Println("---> udpIndex: ", udpIndexInt)

	// var i uint32
	// for i = 0; i < udpIndexInt; i++ {
	// 	udpPacket, err := udpPayloadsMap.GetValue(unsafe.Pointer(&i))
	// 	if err != nil {
	// 		fmt.Fprintln(os.Stderr, err)
	// 	}

	// 	fmt.Println(i, ". ", udpPacket, " = ", string(udpPacket))
	// }

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
