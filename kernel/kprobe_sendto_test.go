package kernel_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/evanrolfe/dockerdog/internal"
	"github.com/evanrolfe/dockerdog/internal/bpf_events"
	"github.com/evanrolfe/dockerdog/internal/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	bpfFilePath       = "bundle/ssl.bpf.o"
	btfFilePath       = "bundle/6.2.0-26-generic.btf"
	sslLibDefault     = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	grpcServerDefault = "localhost:50051"
)

var _ = Describe("kprobe/sendto", func() {
	Context("Todo", Ordered, func() {
		var bpfProg *bpf_events.BPFProgram

		BeforeAll(func() {
			// Extract bundled files
			bpfBytes := internal.MustAsset(bpfFilePath)
			btfBytes := internal.MustAsset(btfFilePath)
			btfDestFile := "./5.8.0-23-generic.btf"
			utils.ExtractFile(btfBytes, btfDestFile)
			defer os.Remove(btfDestFile)

			// Start BPF program
			var err error
			bpfProg, err = bpf_events.NewBPFProgramFromBytes(bpfBytes, btfFilePath, "")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(-1)
			}

			// kprobe sendto
			funcName := fmt.Sprintf("__%s_sys_sendto", ksymArch())
			bpfProg.AttachToKProbe("probe_sendto", funcName)
			bpfProg.AttachToKRetProbe("probe_ret_sendto", funcName)

			// setup channels for bpf ring buffers
			dataEventsChan := make(chan []byte)
			dataEventsBuf, err := bpfProg.BpfModule.InitRingBuf("data_events", dataEventsChan)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(-1)
			}
			dataEventsBuf.Poll(200)

			// Wait for events to be received within timeout limit
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			go func() {
				for {
					// Check if the interrupt signal has been received
					select {
					case <-ctx.Done():
						return

					case payload := <-dataEventsChan:
						fmt.Println("-----------> RECEIVED PAYLOAD", len(payload))
						fmt.Print(hex.Dump(payload))
					}
				}
			}()

			<-ctx.Done()

		})

		BeforeAll(func() {
			bpfProg.Close()
		})

		It("the flow contains the HTTP request", func() {
			Expect(1).To(Equal(1))
		})
	})
})
