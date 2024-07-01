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
	bpf                *BPF
	uprobesByContainer map[string][]*libbpfgo.BPFLink
	uprobes            map[string][]*libbpfgo.BPFLink
	kprobes            map[string]*libbpfgo.BPFLink
	uprobeMutex        sync.Mutex
}

func NewProbeManager(bpf2 *BPF) (*ProbeManager, error) {
	pm := &ProbeManager{
		bpf:                bpf2,
		uprobes:            map[string][]*libbpfgo.BPFLink{},
		uprobesByContainer: map[string][]*libbpfgo.BPFLink{},
		kprobes:            map[string]*libbpfgo.BPFLink{},
	}

	err := pm.loadProgram()
	if err != nil {
		return nil, err
	}

	// TODO:
	// bpf2.LoadProgram()

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

// func (pm *ProbeManager) AttachToKProbes(funcName string, probeFuncName string) error {
// 	sysFuncName := fmt.Sprintf("__%s_sys_accept", ksymArch())
// 	pm.AttachToKProbe("probe_accept4", sysFuncName)
// 	errpm.AttachToKRetProbe("probe_ret_accept4", sysFuncName)

// }

func (pm *ProbeManager) AttachToKProbe(funcName string, probeFuncName string) error {
	bpfLink, err := pm.bpf.AttachKProbe(funcName, probeFuncName)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s-%s", funcName, probeFuncName)
	pm.kprobes[key] = bpfLink
	return nil
}

func (pm *ProbeManager) AttachToKRetProbe(funcName string, probeFuncName string) error {
	bpfLink, err := pm.bpf.AttachKRetProbe(funcName, probeFuncName)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s-%s", funcName, probeFuncName)
	pm.kprobes[key] = bpfLink
	return nil
}

func (pm *ProbeManager) AttachToUProbe(funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error) {
	bpfLink, err := pm.bpf.AttachUProbe(funcName, probeFuncName, binaryPath)
	if err != nil {
		return nil, err
	}
	return bpfLink, nil
}

func (pm *ProbeManager) AttachToURetProbe(funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error) {
	bpfLink, err := pm.bpf.AttachURetProbe(funcName, probeFuncName, binaryPath)
	if err != nil {
		return nil, err
	}
	return bpfLink, nil
}

// AttachGoUProbe attach uprobes to the entry and exits of a Go function. URetProbes will not work with Go.
// Each return statement in the function is an exit which is probed. This will also only work for cryptos/tls.Conn.Read and Write.
// TODO: Should probably just accept a Proc struct instead to avoid primitive obsession
func (pm *ProbeManager) AttachGoUProbes(funcName string, exitFuncName string, probeFuncName string, proc docker.Proc) error {
	pm.uprobeMutex.Lock()
	defer pm.uprobeMutex.Unlock()

	var (
		pid         = proc.Pid
		binaryPath  = proc.ExecPath
		containerId = proc.ContainerId
	)

	// If there are already GoUprobes attached to this binary+func, then dont re-attach thm
	uprobeKey := fmt.Sprintf("%d:%s:%s", pid, binaryPath, probeFuncName)
	_, exists := pm.uprobes[uprobeKey]
	if exists {
		return nil
	}
	pm.uprobes[uprobeKey] = []*libbpfgo.BPFLink{}

	// Also keep track of the uprobes per container
	_, exists = pm.uprobesByContainer[containerId]
	if !exists {
		pm.uprobesByContainer[containerId] = []*libbpfgo.BPFLink{}
	}

	uprobes, err := pm.bpf.AttachGoUProbe(funcName, exitFuncName, probeFuncName, binaryPath)
	if err != nil {
		return fmt.Errorf("error AttachGoUProbes(): %v, error: %v", binaryPath, err)
	}
	pm.uprobes[uprobeKey] = append(pm.uprobes[uprobeKey], uprobes...)

	return nil
}

func (pm *ProbeManager) DetachGoUProbes(probeFuncName string, binaryPath string, pid uint32) error {
	pm.uprobeMutex.Lock()
	defer pm.uprobeMutex.Unlock()

	uprobeKey := fmt.Sprintf("%d:%s:%s", pid, binaryPath, probeFuncName)
	bpfLinks, exists := pm.uprobes[uprobeKey]
	if !exists {
		fmt.Println("No uprobe found for:", probeFuncName, "/", binaryPath)
		return nil
	}

	for _, bpfLink := range bpfLinks {
		fmt.Println("	Destroying Go Uprobe for", binaryPath, "/", probeFuncName)
		err := bpfLink.Destroy()
		if err != nil {
			return fmt.Errorf("bpfLink.Destroy() failed for %s err: %s", uprobeKey, err)
		}
	}
	delete(pm.uprobes, uprobeKey)

	return nil
}

func (pm *ProbeManager) DetachGoUProbesForContainer(containerId string) error {
	pm.uprobeMutex.Lock()
	defer pm.uprobeMutex.Unlock()

	bpfLinks, exists := pm.uprobesByContainer[containerId]
	if !exists {
		fmt.Println("No uprobe found for container:", containerId)
		return nil
	}

	fmt.Println("	Destroying Go Uprobes for container", containerId)
	for _, bpfLink := range bpfLinks {
		err := bpfLink.Destroy()
		if err != nil {
			return fmt.Errorf("bpfLink.Destroy() failed for %s err: %s", containerId, err)
		}
	}
	// TODO:
	// delete(pm.uprobes, uprobeKey)

	return nil
}

func (pm *ProbeManager) DetachAllGoUProbes() error {
	pm.uprobeMutex.Lock()
	defer pm.uprobeMutex.Unlock()

	for uprobeKey, bpfLinks := range pm.uprobes {
		for _, bpfLink := range bpfLinks {
			fmt.Println("	Destroying Go Uprobe for", uprobeKey)
			err := bpfLink.Destroy()
			if err != nil {
				return fmt.Errorf("bpfLink.Destroy() failed for %s err: %s", uprobeKey, err)
			}
		}
		delete(pm.uprobes, uprobeKey)
	}

	return nil
}

func (pm *ProbeManager) DetachAllKProbes() error {
	for key, kprobe := range pm.kprobes {
		fmt.Println("	Destroying kprobe for", key)
		err := kprobe.Destroy()
		if err != nil {
			return fmt.Errorf("kprobe.Destroy() err: %s", err)
		}
		// delete(pm.kprobes, key)
	}
	return nil
}

func (pm *ProbeManager) loadProgram() error {
	return pm.bpf.LoadProgram()
}

func (pm *ProbeManager) Close() {
	fmt.Println("Dettaching BPF program(s)...")
	pm.DetachAllGoUProbes()
	pm.DetachAllKProbes()
	pm.bpf.Close()
}
