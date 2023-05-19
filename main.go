package main

import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

// This works!!!
// Run with:
// make go && ./tc
// cat /sys/kernel/debug/tracing/trace_pipe
//
// TODO:
// 1. Clean up this repo and test from a clean slate
// 2. Commit
// 3. Make it so the log lines are sent from bpf to go

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

	hook.SetAttachPoint(bpf.BPFTcIngress)
	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			fmt.Fprintln(os.Stderr, "tc hook create: %v", err)
		}
	}

	tcProg, err := bpfModule.GetProgram("tc_ingress")
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

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Running, press ctrl+c to exit...")
	<-done // Will block here until user hits ctrl+c

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
