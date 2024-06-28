package bpf_events

import (
	"fmt"
	"os"
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/evanrolfe/trayce_agent/internal/docker"
	"github.com/evanrolfe/trayce_agent/internal/go_offsets"
)

const (
	bufPollRateMs = 50
)

// BPFProgram is a wrapper around bpf.Module and provies helper methods to easily set and remove kprobes, uprobes
// and interact with ebpf.
type BPFProgram struct {
	bpfModule          BPFModuleI
	uprobesByContainer map[string][]*bpf.BPFLink
	uprobes            map[string][]*bpf.BPFLink
	kprobes            map[string]*bpf.BPFLink
	hooksAndOpts       map[*bpf.TcHook]*bpf.TcOpts
	interfaceName      string
	uprobeMutex        sync.Mutex
}

type BPFModuleI interface {
	InitRingBuf(mapName string, eventsChan chan []byte) (*bpf.RingBuffer, error)
	GetMap(mapName string) (*bpf.BPFMap, error)
	GetProgram(progName string) (*bpf.BPFProg, error)
	BPFLoadObject() error
	Close()
}

// TODO: interfaceName should only be required for TC programs
func NewBPFProgram(bpfModule BPFModuleI, interfaceName string) (*BPFProgram, error) {
	prog := &BPFProgram{
		bpfModule:          bpfModule,
		uprobes:            map[string][]*bpf.BPFLink{},
		uprobesByContainer: map[string][]*bpf.BPFLink{},
		hooksAndOpts:       map[*bpf.TcHook]*bpf.TcOpts{},
		kprobes:            map[string]*bpf.BPFLink{},
		interfaceName:      interfaceName,
	}

	err := prog.loadProgram()
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

func (prog *BPFProgram) ReceiveEvents(mapName string, eventsChan chan []byte) error {
	dataEventsBuf, err := prog.bpfModule.InitRingBuf("data_events", eventsChan)
	if err != nil {
		return err
	}
	dataEventsBuf.Poll(bufPollRateMs)

	return nil
}

func (prog *BPFProgram) GetMap(mapName string) (*bpf.BPFMap, error) {
	bpfMap, err := prog.bpfModule.GetMap(mapName)
	if err != nil {
		return nil, err
	}

	return bpfMap, nil
}

func (prog *BPFProgram) AttachToKProbe(funcName string, probeFuncName string) error {
	// Attach Entry Probe
	probeEntry, err := prog.bpfModule.GetProgram(funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfLink, err := probeEntry.AttachKprobe(probeFuncName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	key := fmt.Sprintf("%s-%s", funcName, probeFuncName)
	prog.kprobes[key] = bpfLink
	return nil
}

func (prog *BPFProgram) AttachToKRetProbe(funcName string, probeFuncName string) error {
	// Attach Entry Probe
	probeEntry, err := prog.bpfModule.GetProgram(funcName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfLink, err := probeEntry.AttachKretprobe(probeFuncName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	key := fmt.Sprintf("%s-%s", funcName, probeFuncName)
	prog.kprobes[key] = bpfLink
	return nil
}

func (prog *BPFProgram) AttachToUProbe(funcName string, probeFuncName string, binaryPath string) (*bpf.BPFLink, error) {
	// Get Offset
	offset, err := helpers.SymbolToOffset(binaryPath, probeFuncName)
	if err != nil {
		return nil, err
	}

	// Attach Entry Probe
	probeEntry, err := prog.bpfModule.GetProgram(funcName)
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
	probeReturn, err := prog.bpfModule.GetProgram(funcName)
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
func (prog *BPFProgram) AttachGoUProbes(funcName string, exitFuncName string, probeFuncName string, proc docker.Proc) error {
	prog.uprobeMutex.Lock()
	defer prog.uprobeMutex.Unlock()

	var (
		pid         = proc.Pid
		binaryPath  = proc.ExecPath
		containerId = proc.ContainerId
	)

	// If there are already GoUprobes attached to this binary+func, then dont re-attach thm
	uprobeKey := fmt.Sprintf("%d:%s:%s", pid, binaryPath, probeFuncName)
	_, exists := prog.uprobes[uprobeKey]
	if exists {
		return nil
	}
	prog.uprobes[uprobeKey] = []*bpf.BPFLink{}

	// Also keep track of the uprobes per container
	// TODO: extract the logic for keeping track of uprobes into its own struct
	_, exists = prog.uprobesByContainer[containerId]
	if !exists {
		prog.uprobesByContainer[containerId] = []*bpf.BPFLink{}
	}

	// Get Offset
	gOffsets, err := go_offsets.GetSymbolOffset(binaryPath, probeFuncName)
	if err != nil {
		return fmt.Errorf("GetSymbolOffset() for %v, error: %v", binaryPath, err)
	}

	// Attach Entry Probe
	probeEntry, err := prog.bpfModule.GetProgram(funcName)
	if err != nil {
		return fmt.Errorf("getting ebpf entry probe for: %v, error: %v", binaryPath, err)
	}

	linkEntry, err := probeEntry.AttachUprobe(-1, binaryPath, uint32(gOffsets.Enter))
	if err != nil {
		return fmt.Errorf("attaching ebpf entry probe for: %v, error: %v", binaryPath, err)
	}

	prog.uprobes[uprobeKey] = append(prog.uprobes[uprobeKey], linkEntry)
	prog.uprobesByContainer[containerId] = append(prog.uprobesByContainer[containerId], linkEntry)

	// Exit probe is optional
	if exitFuncName == "" {
		return nil
	}

	// Attach Exit Probe
	for _, exitOffset := range gOffsets.Exits {
		probeExit, err := prog.bpfModule.GetProgram(exitFuncName)
		if err != nil {
			return fmt.Errorf("getting ebpf exit probe for: %v error: %v", binaryPath, err)
		}

		linkExit, err := probeExit.AttachUprobe(-1, binaryPath, uint32(exitOffset))
		if err != nil {
			return fmt.Errorf("attaching ebpf exit probe for: %v error: %v", binaryPath, err)
		}

		prog.uprobes[uprobeKey] = append(prog.uprobes[uprobeKey], linkExit)
		prog.uprobesByContainer[containerId] = append(prog.uprobesByContainer[containerId], linkExit)
	}

	return nil
}

func (prog *BPFProgram) DetachGoUProbes(probeFuncName string, binaryPath string, pid uint32) error {
	prog.uprobeMutex.Lock()
	defer prog.uprobeMutex.Unlock()

	uprobeKey := fmt.Sprintf("%d:%s:%s", pid, binaryPath, probeFuncName)
	bpfLinks, exists := prog.uprobes[uprobeKey]
	if !exists {
		fmt.Println("No uprobe found for:", probeFuncName, "/", binaryPath)
		return nil
	}

	for _, bpfLink := range bpfLinks {
		fmt.Println("	Destroying Go Uprobe for", binaryPath, "/", probeFuncName)
		err := bpfLink.Destroy()
		if err != nil {
			return fmt.Errorf("bpfLink.Destroy() failed for", uprobeKey, "err:", err)
		}
	}
	delete(prog.uprobes, uprobeKey)

	return nil
}

func (prog *BPFProgram) DetachGoUProbesForContainer(containerId string) error {
	prog.uprobeMutex.Lock()
	defer prog.uprobeMutex.Unlock()

	bpfLinks, exists := prog.uprobesByContainer[containerId]
	if !exists {
		fmt.Println("No uprobe found for container:", containerId)
		return nil
	}

	fmt.Println("	Destroying Go Uprobes for container", containerId)
	for _, bpfLink := range bpfLinks {
		err := bpfLink.Destroy()
		if err != nil {
			return fmt.Errorf("bpfLink.Destroy() failed for", containerId, "err:", err)
		}
	}
	// TODO:
	// delete(prog.uprobes, uprobeKey)

	return nil
}

func (prog *BPFProgram) DetachAllGoUProbes() error {
	prog.uprobeMutex.Lock()
	defer prog.uprobeMutex.Unlock()

	for uprobeKey, bpfLinks := range prog.uprobes {
		for _, bpfLink := range bpfLinks {
			fmt.Println("	Destroying Go Uprobe for", uprobeKey)
			err := bpfLink.Destroy()
			if err != nil {
				return fmt.Errorf("bpfLink.Destroy() failed for", uprobeKey, "err:", err)
			}
		}
		delete(prog.uprobes, uprobeKey)
	}

	return nil
}

func (prog *BPFProgram) DetachAllKProbes() error {
	for key, kprobe := range prog.kprobes {
		fmt.Println("	Destroying kprobe for", key)
		err := kprobe.Destroy()
		if err != nil {
			return fmt.Errorf("kprobe.Destroy() err:", err)
		}
		// delete(prog.kprobes, key)
	}
	return nil
}

func (prog *BPFProgram) loadProgram() error {
	return prog.bpfModule.BPFLoadObject()
}

func (prog *BPFProgram) Close() {
	fmt.Println("Dettaching BPF program(s)...")
	prog.DetachAllGoUProbes()
	prog.DetachAllKProbes()
	prog.bpfModule.Close()
}
