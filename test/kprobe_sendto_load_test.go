package test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/evanrolfe/dockerdog/internal"
	"github.com/evanrolfe/dockerdog/internal/bpf_events"
	"github.com/evanrolfe/dockerdog/internal/utils"
	"github.com/stretchr/testify/assert"
)

const (
	bpfFilePath = "bundle/ssl.bpf.o"
	btfFilePath = "bundle/6.2.0-26-generic.btf"
)

func removeDuplicate[T string | int](sliceList []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func ksymArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		panic("unsupported architecture")
	}
}

func setupProbe() (*bpf_events.BPFProgram, chan []byte, chan []byte) {
	// Extract bundled files
	bpfBytes := internal.MustAsset(bpfFilePath)
	btfBytes := internal.MustAsset(btfFilePath)
	btfDestFile := "./5.8.0-23-generic.btf"
	utils.ExtractFile(btfBytes, btfDestFile)
	defer os.Remove(btfDestFile)

	// Start BPF program
	var err error
	bpfProg, err := bpf_events.NewBPFProgramFromBytes(bpfBytes, btfFilePath, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// DataEvents ring buffer
	dataEventsChan := make(chan []byte)
	dataEventsBuf, err := bpfProg.BpfModule.InitRingBuf("data_events", dataEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// ConnectEvents ring buffer
	connectEventsChan := make(chan []byte)
	connectEventsBuf, err := bpfProg.BpfModule.InitRingBuf("connect_events", connectEventsChan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	dataEventsBuf.Poll(10)
	connectEventsBuf.Poll(10)

	return bpfProg, dataEventsChan, connectEventsChan
}

func Test_kprobe_sendto_load(t *testing.T) {
	// if testing.Short() {
	t.Skip()
	// }

	totalCount := 100

	var bpfProg *bpf_events.BPFProgram
	dataEvents := []bpf_events.DataEvent{}
	randValues := []int{}

	bpfProg2, dataEventsChan, _ := setupProbe()
	bpfProg = bpfProg2

	// Attach kprobe/sendto
	funcName := fmt.Sprintf("__%s_sys_sendto", ksymArch())
	bpfProg.AttachToKProbe("probe_sendto", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_sendto", funcName)

	// Wait for events to be received within timeout limit
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Start listening for events async
	go func() {
		for {
			// Check if the interrupt signal has been received
			select {
			case <-ctx.Done():
				return

			case payload := <-dataEventsChan:
				event := bpf_events.DataEvent{}
				event.Decode(payload)
				httpReq := string(event.Payload())
				if strings.Contains(httpReq, "Host: www.pntest.io") && strings.Contains(httpReq, "GET / HTTP/1.1") {
					dataEvents = append(dataEvents, event)
					randValues = append(randValues, int(event.Rand))

					fmt.Println("Got ", len(dataEvents), " events so far")
					fmt.Println("[DataEvent] Received ", event.DataLen, "bytes, type:", event.DataType, ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, "Rand:", event.Rand)
					// fmt.Println(hex.Dump(event.Payload()))
				}
			}
		}
	}()

	// Make an HTTP request which should trigger the event from kprobe/sendto
	cmd := exec.Command(requestRubyScriptHttpLoad, "http://www.pntest.io/", fmt.Sprint(totalCount))
	cmd.Start()

	<-ctx.Done()

	uniqRands := removeDuplicate(randValues)

	assert.Equal(t, len(dataEvents), totalCount)
	assert.Equal(t, len(uniqRands), totalCount)

	bpfProg.Close()
}
