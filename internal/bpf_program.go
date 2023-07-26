package internal

import "C"

import (
	"fmt"
	"os"
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
	prog2, err := prog.BpfModule.GetProgram(funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog2.AttachURetprobe(-1, binaryPath, offset)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	return nil
}

func (prog *BPFProgram) LoadProgram() error {
	return prog.BpfModule.BPFLoadObject()
}

func (prog *BPFProgram) Close() {
	fmt.Println("Dettaching TC program(s)...")
	defer prog.BpfModule.Close()

	for hook, tcOpts := range prog.hooksAndOpts {
		fmt.Println("Detaching hook:", hook, " from handle:", tcOpts.Handle, "Priority:", tcOpts.Priority)
		tcOpts.ProgFd = 0
		tcOpts.ProgId = 0
		tcOpts.Flags = 0

		err := hook.Detach(tcOpts)
		if err != nil {
			fmt.Println(err)
			break
		}

		err = hook.Destroy()
		if err != nil {
			fmt.Println("failed to destroy hook:", err)
		}
	}
}
