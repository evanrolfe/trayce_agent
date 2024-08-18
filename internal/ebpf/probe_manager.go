package ebpf

import (
	"fmt"
	"sync"

	"github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/trayce_agent/internal/docker"
)

const (
	bufPollRateMs = 50
)

// ProbeManager lets you add & remove ebpf probes. It keeps track of them so they can be deleted too when necessary.
type ProbeManager struct {
	bpf         BPFI
	kprobes     []*libbpfgo.BPFLink
	probeRefs   []*ProbeRef
	uprobeMutex sync.Mutex
}

type ProbeRef struct {
	probe       *libbpfgo.BPFLink
	containerID string
	binaryPath  string
	pid         uint32
}

type BPFI interface {
	GetMap(mapName string) (*libbpfgo.BPFMap, error)
	InitRingBuf(mapName string, eventsChan chan []byte) (*libbpfgo.RingBuffer, error)
	LoadProgram() error
	Close()
	AttachKProbe(funcName string, probeFuncName string) (*libbpfgo.BPFLink, error)
	AttachKRetProbe(funcName string, probeFuncName string) (*libbpfgo.BPFLink, error)
	AttachUProbe(funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error)
	AttachURetProbe(funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error)
	AttachGoUProbe(funcName string, exitFuncName string, probeFuncName string, binaryPath string) ([]*libbpfgo.BPFLink, error)
	DestroyProbe(probe *libbpfgo.BPFLink) error
}

func NewProbeManager(bpf BPFI) (*ProbeManager, error) {
	err := bpf.LoadProgram()
	if err != nil {
		return nil, err
	}

	pm := &ProbeManager{
		bpf:       bpf,
		kprobes:   []*libbpfgo.BPFLink{},
		probeRefs: []*ProbeRef{},
	}

	return pm, nil
}

func NewProbeManagerFromFileArgs(bpfPath string, btfPath string) (*ProbeManager, error) {
	bpfModule, err := libbpfgo.NewModuleFromFileArgs(libbpfgo.NewModuleArgs{
		BPFObjPath: bpfPath,
		BTFObjPath: btfPath,
	})
	if err != nil {
		return nil, err
	}

	bpf := NewBPF(bpfModule)

	return NewProbeManager(bpf)
}

func NewProbeManagerFromBytes(bpfBuf []byte, btfPath string) (*ProbeManager, error) {
	bpfModule, err := libbpfgo.NewModuleFromBufferArgs(libbpfgo.NewModuleArgs{
		BPFObjBuff: bpfBuf,
		BPFObjName: "main.bpf.o",
	})
	if err != nil {
		return nil, err
	}

	bpf := NewBPF(bpfModule)

	return NewProbeManager(bpf)
}

func (pm *ProbeManager) ReceiveEvents(mapName string, eventsChan chan []byte) error {
	dataEventsBuf, err := pm.bpf.InitRingBuf("data_events", eventsChan)
	if err != nil {
		return err
	}
	dataEventsBuf.Poll(bufPollRateMs)

	return nil
}

func (pm *ProbeManager) GetMap(mapName string) (*libbpfgo.BPFMap, error) {
	bpfMap, err := pm.bpf.GetMap(mapName)
	if err != nil {
		return nil, err
	}

	return bpfMap, nil
}

func (pm *ProbeManager) AttachToKProbe(funcName string, probeFuncName string) error {
	bpfLink, err := pm.bpf.AttachKProbe(funcName, probeFuncName)
	if err != nil {
		return err
	}
	pm.kprobes = append(pm.kprobes, bpfLink)
	return nil
}

func (pm *ProbeManager) AttachToKRetProbe(funcName string, probeFuncName string) error {
	bpfLink, err := pm.bpf.AttachKRetProbe(funcName, probeFuncName)
	if err != nil {
		return err
	}
	pm.kprobes = append(pm.kprobes, bpfLink)
	return nil
}

func (pm *ProbeManager) AttachToUProbe(container docker.Container, funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error) {
	pm.uprobeMutex.Lock()
	defer pm.uprobeMutex.Unlock()

	bpfLink, err := pm.bpf.AttachUProbe(funcName, probeFuncName, binaryPath)
	if err != nil {
		return nil, err
	}

	ref := &ProbeRef{containerID: container.ID, binaryPath: binaryPath, probe: bpfLink, pid: 0} // PID=0 means this is for any proc using this binary
	pm.probeRefs = append(pm.probeRefs, ref)

	return bpfLink, nil
}

func (pm *ProbeManager) AttachToURetProbe(container docker.Container, funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error) {
	pm.uprobeMutex.Lock()
	defer pm.uprobeMutex.Unlock()

	bpfLink, err := pm.bpf.AttachURetProbe(funcName, probeFuncName, binaryPath)
	if err != nil {
		return nil, err
	}

	ref := &ProbeRef{containerID: container.ID, binaryPath: binaryPath, probe: bpfLink, pid: 0}
	pm.probeRefs = append(pm.probeRefs, ref)

	return bpfLink, nil
}

// AttachGoUProbe attach uprobes to the entry and exits of a Go function. URetProbes will not work with Go.
// Each return statement in the function is an exit which is probed. This will also only work for cryptos/tls.Conn.Read and Write.
func (pm *ProbeManager) AttachGoUProbes(proc docker.Proc, funcName string, exitFuncName string, probeFuncName string) error {
	pm.uprobeMutex.Lock()
	defer pm.uprobeMutex.Unlock()

	var (
		pid         = proc.PID
		binaryPath  = proc.ExecPath
		containerId = proc.ContainerId
	)

	uprobes, err := pm.bpf.AttachGoUProbe(funcName, exitFuncName, probeFuncName, binaryPath)
	if err != nil {
		return fmt.Errorf("error AttachGoUProbes(): %v, error: %v", binaryPath, err)
	}

	for _, uprobe := range uprobes {
		ref := &ProbeRef{containerID: containerId, binaryPath: binaryPath, probe: uprobe, pid: pid}
		pm.probeRefs = append(pm.probeRefs, ref)
	}

	// For short lived-requests it might not have time to get the execpath so we just skip it
	if binaryPath == "" {
		return nil
	}

	return nil
}

func (pm *ProbeManager) DetachUprobesForContainer(container docker.Container) error {
	pm.uprobeMutex.Lock()
	defer pm.uprobeMutex.Unlock()

	newProbeRefs := []*ProbeRef{}
	for _, probeRef := range pm.probeRefs {
		if probeRef.containerID == container.ID {
			err := pm.bpf.DestroyProbe(probeRef.probe)
			if err != nil {
				return err
			}
		} else {
			newProbeRefs = append(newProbeRefs, probeRef)
		}
	}

	pm.probeRefs = newProbeRefs
	return nil
}

func (pm *ProbeManager) DetachUprobesForProc(proc docker.Proc) error {
	pm.uprobeMutex.Lock()
	defer pm.uprobeMutex.Unlock()

	newProbeRefs := []*ProbeRef{}
	for _, probeRef := range pm.probeRefs {
		if probeRef.containerID == proc.ContainerId && probeRef.binaryPath == proc.ExecPath && probeRef.pid == proc.PID {
			err := pm.bpf.DestroyProbe(probeRef.probe)
			if err != nil {
				return err
			}
		} else {
			newProbeRefs = append(newProbeRefs, probeRef)
		}
	}

	pm.probeRefs = newProbeRefs
	return nil
}

func (pm *ProbeManager) detachAllUProbes() error {
	pm.uprobeMutex.Lock()
	defer pm.uprobeMutex.Unlock()

	for _, probeRef := range pm.probeRefs {
		err := pm.bpf.DestroyProbe(probeRef.probe)
		if err != nil {
			return err
		}
	}

	pm.probeRefs = []*ProbeRef{}
	return nil
}

func (pm *ProbeManager) detachAllKProbes() error {
	for _, kprobe := range pm.kprobes {
		fmt.Println("	Destroying kprobe for", kprobe)
		err := pm.bpf.DestroyProbe(kprobe)
		if err != nil {
			return fmt.Errorf("kprobe.Destroy() err: %s", err)
		}
	}

	pm.kprobes = []*libbpfgo.BPFLink{}
	return nil
}

func (pm *ProbeManager) Close() {
	fmt.Println("Dettaching BPF program(s)...")
	pm.detachAllUProbes()
	pm.detachAllKProbes()
	pm.bpf.Close()
}
