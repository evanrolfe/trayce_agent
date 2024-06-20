package bpf_events

import (
	"fmt"
	"os"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/evanrolfe/trayce_agent/internal/go_offsets"
)

type BPFProgram struct {
	BpfModule     *bpf.Module
	uprobes       map[string][]*bpf.BPFLink
	hooksAndOpts  map[*bpf.TcHook]*bpf.TcOpts
	interfaceName string
}

// TODO: interfaceName should only be required for TC programs
func NewBPFProgram(bpfModule *bpf.Module, interfaceName string) (*BPFProgram, error) {
	prog := &BPFProgram{
		BpfModule:     bpfModule,
		uprobes:       map[string][]*bpf.BPFLink{},
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

func (prog *BPFProgram) AttachToUProbe(funcName string, probeFuncName string, binaryPath string) (*bpf.BPFLink, error) {
	// Get Offset
	offset, err := helpers.SymbolToOffset(binaryPath, probeFuncName)
	if err != nil {
		return nil, err
	}

	// Attach Entry Probe
	probeEntry, err := prog.BpfModule.GetProgram(funcName)
	if err != nil {
		return nil, err
	}

	bpfLink, err := probeEntry.AttachUprobe(-1, binaryPath, offset)
	if err != nil {
		return nil, err
	}

	return bpfLink, nil
}

func (prog *BPFProgram) AttachToURetProbe(funcName string, probeFuncName string, binaryPath string) (*bpf.BPFLink, error) {
	// Get Offset
	offset, err := helpers.SymbolToOffset(binaryPath, probeFuncName)
	if err != nil {
		return nil, fmt.Errorf("helpers.SymbolToOffset() for: %v, error: %v", binaryPath, err)
	}

	// Attach Return Probe
	probeReturn, err := prog.BpfModule.GetProgram(funcName)
	if err != nil {
		return nil, fmt.Errorf("BpfModule.GetProgram() for: %v, error: %v", binaryPath, err)
	}

	bpfLink, err := probeReturn.AttachURetprobe(-1, binaryPath, offset)
	if err != nil {
		return nil, fmt.Errorf("AttachURetprobe() for: %v, error: %v", binaryPath, err)
	}
	return bpfLink, nil
}

// AttachGoUProbe attach uprobes to the entry and exits of a Go function. URetProbes will not work with Go.
// Each return statement in the function is an exit which is probed. This will also only work for cryptos/tls.Conn.Read and Write.
// TODO: Should probably just accept a Proc struct instead to avoid primitive obsession
func (prog *BPFProgram) AttachGoUProbes(funcName string, exitFuncName string, probeFuncName string, binaryPath string, pid uint32) error {
	// If there are already GoUprobes attached to this binary+func, then dont re-attach thm
	uprobeKey := fmt.Sprintf("%d:%s:%s", pid, binaryPath, probeFuncName)
	_, exists := prog.uprobes[uprobeKey]
	if exists {
		return nil
	}
	prog.uprobes[uprobeKey] = []*bpf.BPFLink{}

	// Get Offset
	gOffsets, err := go_offsets.GetSymbolOffset(binaryPath, probeFuncName)
	if err != nil {
		return fmt.Errorf("GetSymbolOffset() for %v, error: %v", binaryPath, err)
	}

	// Attach Entry Probe
	probeEntry, err := prog.BpfModule.GetProgram(funcName)
	if err != nil {
		return fmt.Errorf("getting ebpf entry probe for: %v, error: %v", binaryPath, err)
	}

	linkEntry, err := probeEntry.AttachUprobe(-1, binaryPath, uint32(gOffsets.Enter))
	if err != nil {
		return fmt.Errorf("attaching ebpf entry probe for: %v, error: %v", binaryPath, err)
	}

	prog.uprobes[uprobeKey] = append(prog.uprobes[uprobeKey], linkEntry)
	// linkEntry.Destroy()

	// Exit probe is optional
	if exitFuncName == "" {
		return nil
	}

	// Attach Exit Probe
	for _, exitOffset := range gOffsets.Exits {
		probeExit, err := prog.BpfModule.GetProgram(exitFuncName)
		if err != nil {
			return fmt.Errorf("getting ebpf exit probe for: %v error: %v", binaryPath, err)
		}

		linkExit, err := probeExit.AttachUprobe(-1, binaryPath, uint32(exitOffset))
		if err != nil {
			return fmt.Errorf("attaching ebpf exit probe for: %v error: %v", binaryPath, err)
		}

		prog.uprobes[uprobeKey] = append(prog.uprobes[uprobeKey], linkExit)
	}

	return nil
}

func (prog *BPFProgram) DetachGoUProbes(probeFuncName string, binaryPath string, pid uint32) error {
	uprobeKey := fmt.Sprintf("%d:%s:%s", pid, binaryPath, probeFuncName)
	bpfLinks, exists := prog.uprobes[uprobeKey]
	if !exists {
		return nil
	}

	for _, bpfLink := range bpfLinks {
		fmt.Println("	Destroying Go Uprobe for", binaryPath, "/", probeFuncName)
		err := bpfLink.Destroy()
		if err != nil {
			return fmt.Errorf("bpfLink.Destroy() failed for", uprobeKey, "err:", err)
		}
	}
	return nil
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
