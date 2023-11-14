package bpf_events

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

type BPFProgram struct {
	BpfModule     *bpf.Module
	hooksAndOpts  map[*bpf.TcHook]*bpf.TcOpts
	interfaceName string
}

// TODO: interfaceName should only be required for TC programs
func NewBPFProgram(bpfModule *bpf.Module, interfaceName string) (*BPFProgram, error) {
	prog := &BPFProgram{
		BpfModule:     bpfModule,
		hooksAndOpts:  map[*bpf.TcHook]*bpf.TcOpts{},
		interfaceName: interfaceName,
	}

	err := prog.LoadProgram()
	if err != nil {
		return nil, err
	}

	return prog, nil
}

func NewBPFProgramFromFileArgs(bpfPath string, btfPath string, interfaceName string) (*BPFProgram, error) {
	bpfModule, err := bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath: bpfPath,
		BTFObjPath: btfPath,
	})
	if err != nil {
		return nil, err
	}

	return NewBPFProgram(bpfModule, interfaceName)
}

func NewBPFProgramFromBytes(bpfBuf []byte, btfPath string, interfaceName string) (*BPFProgram, error) {
	bpfModule, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
		BPFObjBuff: bpfBuf,
		BPFObjName: "main.bpf.o",
	})
	if err != nil {
		return nil, err
	}

	return NewBPFProgram(bpfModule, interfaceName)
}

func (prog *BPFProgram) AttachToTC(tcFuncName string, attachPoint bpf.TcAttachPoint) (*bpf.TcHook, *bpf.TcOpts, error) {
	hook := prog.BpfModule.TcHookInit()
	err := hook.SetInterfaceByName(prog.interfaceName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to set tc hook on interface eth0: %v", err)
		os.Exit(-1)
	}

	hook.SetAttachPoint(attachPoint)
	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			fmt.Fprintln(os.Stderr, "tc hook create: %v", err)
		}
	}

	tcProg, err := prog.BpfModule.GetProgram(tcFuncName)
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

	prog.hooksAndOpts[hook] = &tcOpts

	return hook, &tcOpts, nil
}

func (prog *BPFProgram) AttachToKProbe(funcName string, probeFuncName string) error {
	// Attach Entry Probe
	probeEntry, err := prog.BpfModule.GetProgram(funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = probeEntry.AttachKprobe(probeFuncName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	return nil
}

func (prog *BPFProgram) AttachToKRetProbe(funcName string, probeFuncName string) error {
	// Attach Entry Probe
	probeEntry, err := prog.BpfModule.GetProgram(funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = probeEntry.AttachKretprobe(probeFuncName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	return nil
}

func (prog *BPFProgram) AttachToUProbe(funcName string, probeFuncName string, binaryPath string) error {
	// Get Offset
	offset, err := helpers.SymbolToOffset(binaryPath, probeFuncName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// Attach Entry Probe
	probeEntry, err := prog.BpfModule.GetProgram(funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = probeEntry.AttachUprobe(-1, binaryPath, offset)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	return nil
}

func (prog *BPFProgram) AttachToURetProbe(funcName string, probeFuncName string, binaryPath string) error {
	// Get Offset
	offset, err := helpers.SymbolToOffset(binaryPath, probeFuncName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// Attach Return Probe
	probeReturn, err := prog.BpfModule.GetProgram(funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = probeReturn.AttachURetprobe(-1, binaryPath, offset)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	return nil
}

// AttachGoUProbe attach uprobes to the entry and exits of a Go function. URetProbes will not work with Go.
// Each return statement in the function is an exit which is probed. This will also only work for cryptos/tls.Conn.Read and Write.
func (prog *BPFProgram) AttachGoUProbes(funcName string, exitFuncName string, probeFuncName string, binaryPath string) *goOffsets {
	// Get Offset
	gOffsets, err := findGoOffsets(binaryPath)

	var enterOffset uint64
	var exitOffsets []uint64
	// TODO: Get rid of this hacky check and make this work with all Go functions, not just Conn.Read and Write
	if strings.Contains(probeFuncName, "Read") {
		enterOffset = gOffsets.GoReadOffset.enter
		exitOffsets = gOffsets.GoReadOffset.exits
	} else {
		enterOffset = gOffsets.GoWriteOffset.enter
		exitOffsets = gOffsets.GoWriteOffset.exits
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// Attach Entry Probe
	probeEntry, err := prog.BpfModule.GetProgram(funcName)
	if err != nil {
		panic(err)
	}

	_, err = probeEntry.AttachUprobe(-1, binaryPath, uint32(enterOffset))
	if err != nil {
		panic(err)
	}

	// Exit probe is optional
	if exitFuncName == "" {
		return &gOffsets
	}

	// Attach Exit Probe
	for _, exitOffset := range exitOffsets {
		probeExit, err := prog.BpfModule.GetProgram(exitFuncName)
		if err != nil {
			panic(err)
		}

		_, err = probeExit.AttachUprobe(-1, binaryPath, uint32(exitOffset))
		if err != nil {
			panic(err)
		}
		fmt.Println("attached to exit offset:", exitOffset)
	}

	return &gOffsets
}

func (prog *BPFProgram) LoadProgram() error {
	return prog.BpfModule.BPFLoadObject()
}

func (prog *BPFProgram) Close() {
	fmt.Println("Dettaching TC program(s)...")
	prog.BpfModule.Close()
	// defer prog.BpfModule.Close()

	// for hook, tcOpts := range prog.hooksAndOpts {
	// 	fmt.Println("Detaching hook:", hook, " from handle:", tcOpts.Handle, "Priority:", tcOpts.Priority)
	// 	tcOpts.ProgFd = 0
	// 	tcOpts.ProgId = 0
	// 	tcOpts.Flags = 0

	// 	err := hook.Detach(tcOpts)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		break
	// 	}

	// 	err = hook.Destroy()
	// 	if err != nil {
	// 		fmt.Println("failed to destroy hook:", err)
	// 	}
	// }
}
