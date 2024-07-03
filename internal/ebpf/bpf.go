package ebpf

import (
	"fmt"

	"github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"github.com/evanrolfe/trayce_agent/internal/go_offsets"
)

// BPF is a wrapper around libbpfgo.BPFModule and provides methods for create/deleting probes and also fetching data
// from ebpf maps.
type BPF struct {
	bpfModule BPFModuleI
}

type BPFModuleI interface {
	InitRingBuf(mapName string, eventsChan chan []byte) (*libbpfgo.RingBuffer, error)
	GetMap(mapName string) (*libbpfgo.BPFMap, error)
	GetProgram(progName string) (*libbpfgo.BPFProg, error)
	BPFLoadObject() error
	Close()
}

func NewBPF(bpfModule BPFModuleI) *BPF {
	bpf := &BPF{
		bpfModule: bpfModule,
	}

	return bpf
}

func (bpf *BPF) GetMap(mapName string) (*libbpfgo.BPFMap, error) {
	return bpf.bpfModule.GetMap(mapName)
}

func (bpf *BPF) InitRingBuf(mapName string, eventsChan chan []byte) (*libbpfgo.RingBuffer, error) {
	return bpf.bpfModule.InitRingBuf(mapName, eventsChan)
}

func (bpf *BPF) LoadProgram() error {
	return bpf.bpfModule.BPFLoadObject()
}

func (bpf *BPF) Close() {
	bpf.bpfModule.Close()
}

func (bpf *BPF) AttachKProbe(funcName string, probeFuncName string) (*libbpfgo.BPFLink, error) {
	// Attach Entry Probe
	probeEntry, err := bpf.bpfModule.GetProgram(funcName)
	if err != nil {
		return nil, err
	}

	bpfLink, err := probeEntry.AttachKprobe(probeFuncName)
	if err != nil {
		return nil, err
	}

	return bpfLink, nil
}

func (bpf *BPF) AttachKRetProbe(funcName string, probeFuncName string) (*libbpfgo.BPFLink, error) {
	// Attach Entry Probe
	probeEntry, err := bpf.bpfModule.GetProgram(funcName)
	if err != nil {
		return nil, err
	}

	bpfLink, err := probeEntry.AttachKretprobe(probeFuncName)
	if err != nil {
		return nil, err
	}

	return bpfLink, nil
}

func (bpf *BPF) AttachUProbe(funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error) {
	offset, err := helpers.SymbolToOffset(binaryPath, probeFuncName)
	if err != nil {
		return nil, err
	}

	probeEntry, err := bpf.bpfModule.GetProgram(funcName)
	if err != nil {
		return nil, err
	}

	bpfLink, err := probeEntry.AttachUprobe(-1, binaryPath, offset)
	if err != nil {
		return nil, err
	}

	return bpfLink, nil
}

func (bpf *BPF) AttachURetProbe(funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error) {
	offset, err := helpers.SymbolToOffset(binaryPath, probeFuncName)
	if err != nil {
		return nil, fmt.Errorf("helpers.SymbolToOffset() for: %v, error: %v", binaryPath, err)
	}

	probeReturn, err := bpf.bpfModule.GetProgram(funcName)
	if err != nil {
		return nil, fmt.Errorf("BpfModule.GetProgram() for: %v, error: %v", binaryPath, err)
	}

	bpfLink, err := probeReturn.AttachURetprobe(-1, binaryPath, offset)
	if err != nil {
		return nil, fmt.Errorf("AttachURetprobe() for: %v, error: %v", binaryPath, err)
	}
	return bpfLink, nil
}

func (bpf *BPF) AttachGoUProbe(funcName string, exitFuncName string, probeFuncName string, binaryPath string) ([]*libbpfgo.BPFLink, error) {
	uprobes := []*libbpfgo.BPFLink{}

	// Get Offset
	gOffsets, err := go_offsets.GetSymbolOffset(binaryPath, probeFuncName)
	if err != nil {
		return uprobes, fmt.Errorf("GetSymbolOffset() for %v, error: %v", binaryPath, err)
	}

	// Attach Entry Probe
	probeEntry, err := bpf.bpfModule.GetProgram(funcName)
	if err != nil {
		return uprobes, fmt.Errorf("getting ebpf entry probe for: %v, error: %v", binaryPath, err)
	}

	linkEntry, err := probeEntry.AttachUprobe(-1, binaryPath, uint32(gOffsets.Enter))
	if err != nil {
		return uprobes, fmt.Errorf("attaching ebpf entry probe for: %v, error: %v", binaryPath, err)
	}
	uprobes = append(uprobes, linkEntry)

	// Exit probe is optional
	if exitFuncName == "" {
		return uprobes, nil
	}

	// Attach exit probes
	for _, exitOffset := range gOffsets.Exits {
		probeExit, err := bpf.bpfModule.GetProgram(exitFuncName)
		if err != nil {
			return uprobes, fmt.Errorf("getting ebpf exit probe for: %v error: %v", binaryPath, err)
		}

		linkExit, err := probeExit.AttachUprobe(-1, binaryPath, uint32(exitOffset))
		if err != nil {
			return uprobes, fmt.Errorf("attaching ebpf exit probe for: %v error: %v", binaryPath, err)
		}

		uprobes = append(uprobes, linkExit)
	}

	return uprobes, nil
}

func (bpf *BPF) DestroyProbe(probe *libbpfgo.BPFLink) error {
	return probe.Destroy()
}
