package internal

import "C"

import (
	"fmt"
	"os"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

type BPFProgram struct {
	BpfModule     *bpf.Module
	hooksAndOpts  map[*bpf.TcHook]*bpf.TcOpts
	interfaceName string
	tcFuncName    string
}

func NewBPFProgram(bpfModule *bpf.Module, interfaceName string, tcFuncName string) (*BPFProgram, error) {
	prog := &BPFProgram{
		BpfModule:     bpfModule,
		hooksAndOpts:  map[*bpf.TcHook]*bpf.TcOpts{},
		interfaceName: interfaceName,
		tcFuncName:    tcFuncName,
	}

	err := prog.LoadProgram()
	if err != nil {
		return nil, err
	}

	return prog, nil
}

func NewBPFProgramFromFileArgs(bpfPath string, btfPath string, interfaceName string, tcFuncName string) (*BPFProgram, error) {
	bpfModule, err := bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath: bpfPath,
		BTFObjPath: btfPath,
	})
	if err != nil {
		return nil, err
	}

	return NewBPFProgram(bpfModule, interfaceName, tcFuncName)
}

func (prog *BPFProgram) AttachToTC(attachPoint bpf.TcAttachPoint) (*bpf.TcHook, *bpf.TcOpts, error) {
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

	tcProg, err := prog.BpfModule.GetProgram(prog.tcFuncName)
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
