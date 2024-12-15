package ebpf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/trayce_agent/internal/docker"
	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/evanrolfe/trayce_agent/internal/go_offsets"
)

const (
	containerPIDsRefreshRate = 50 * time.Millisecond
)

// Stream is a bridge between the docker client and ebpf. When new containers and proccesses are opened, it instruments
// them with ebpf probes. It also provides an event stream channel which gives us the Connect,Data and Close events that
// are sent from ebpf.
type Stream struct {
	probeManager ProbeManagerI
	containers   ContainersI

	cgroupMap         *libbpfgo.BPFMap
	goOffsetsMap      *libbpfgo.BPFMap
	libSSLVersionsMap *libbpfgo.BPFMap
	dataEventsChan    chan []byte
	interruptChan     chan int

	connectCallbacks []func(events.ConnectEvent)
	dataCallbacks    []func(events.DataEvent)
	closeCallbacks   []func(events.CloseEvent)
}

type ContainersI interface {
	GetProcsToIntercept() map[uint32]docker.Proc
	GetContainersToIntercept() map[string]docker.Container
}

type ProbeManagerI interface {
	AttachToKProbe(funcName string, probeFuncName string) error
	AttachToKRetProbe(funcName string, probeFuncName string) error
	AttachTracepoint(funcName string, category string, probeFuncName string) error
	ReceiveEvents(mapName string, eventsChan chan []byte) error
	GetMap(mapName string) (*libbpfgo.BPFMap, error)
	AttachToUProbe(container docker.Container, funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error)
	AttachToURetProbe(container docker.Container, funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error)
	AttachGoUProbes(proc docker.Proc, funcName string, exitFuncName string, probeFuncName string) error
	DetachUprobesForContainer(container docker.Container) error
	DetachUprobesForProc(proc docker.Proc) error
	Close()
}

type offsets struct {
	goFdOffset uint64
}

func NewStream(containers ContainersI, probeManager ProbeManagerI) *Stream {
	return &Stream{
		probeManager:   probeManager,
		containers:     containers,
		interruptChan:  make(chan int),
		dataEventsChan: make(chan []byte, 10000),
		// Init to empy structs
		cgroupMap:         &libbpfgo.BPFMap{},
		goOffsetsMap:      &libbpfgo.BPFMap{},
		libSSLVersionsMap: &libbpfgo.BPFMap{},
	}
}

func (stream *Stream) AddConnectCallback(callback func(events.ConnectEvent)) {
	stream.connectCallbacks = append(stream.connectCallbacks, callback)
}

func (stream *Stream) AddDataCallback(callback func(events.DataEvent)) {
	stream.dataCallbacks = append(stream.dataCallbacks, callback)
}

func (stream *Stream) AddCloseCallback(callback func(events.CloseEvent)) {
	stream.closeCallbacks = append(stream.closeCallbacks, callback)
}

func (stream *Stream) Start(outputChan chan events.IEvent) {
	stream.attachProbes()

	// events.DataEvents ring buffer
	err := stream.probeManager.ReceiveEvents("data_events", stream.dataEventsChan)
	if err != nil {
		panic(err)
	}

	// Intercepted PIDs map
	cgroupMap, err := stream.probeManager.GetMap("cgroup_name_hashes")
	if err != nil {
		panic(err)
	}
	stream.cgroupMap = cgroupMap
	go stream.refreshPids()

	// Offsets map
	goOffsetsMap, err := stream.probeManager.GetMap("offsets_map")
	if err != nil {
		panic(err)
	}
	stream.goOffsetsMap = goOffsetsMap

	// libssl versions map
	libSSLVersionsMap, err := stream.probeManager.GetMap("libssl_versions_map")
	if err != nil {
		panic(err)
	}
	stream.libSSLVersionsMap = libSSLVersionsMap

	// colours
	red := "\033[35m"
	cyan := "\033[36m"
	reset := "\033[0m"

	for {
		// Check if the interrupt signal has been received
		select {
		case <-stream.interruptChan:
			return

		case payload := <-stream.dataEventsChan:
			eventType := getEventType(payload)

			// events.ConnectEvent
			if eventType == 0 {
				event := events.ConnectEvent{}
				event.Decode(payload)

				fmt.Printf("%s[ConnectEvent]%s PID: %d, TID: %d, FD: %d, source: %s, %s=>%s cgroup: %s\n", cyan, reset, event.PID, event.TID, event.FD, event.TypeStr(), event.SourceAddr(), event.DestAddr(), event.CGroupName())
				outputChan <- &event

				// events.DataEvent
			} else if eventType == 1 {
				event := events.DataEvent{}
				err = event.Decode(payload)
				if err != nil {
					fmt.Println("[ERROR] failed to decode")
					panic(err)
				}
				if event.IsBlank() {
					fmt.Println("\n[DataEvent] Received", event.DataLen, "bytes [ALL BLANK, DROPPING]")
					continue
				}

				outputChan <- &event

			} else if eventType == 2 {
				event := events.CloseEvent{}
				event.Decode(payload)

				fmt.Printf("%s[CloseEvent]%s PID: %d, TID: %d, FD: %d\n", red, reset, event.PID, event.TID, event.FD)
				outputChan <- &event

				// DebugEvent
			} else if eventType == 3 {
				event := events.DebugEvent{}
				event.Decode(payload)

				fmt.Println("\n[DebugEvent] Received, PID:", event.PID, ", TID:", event.TID, "FD: ", event.FD, " - ", string(event.Payload()))
				fmt.Print(hex.Dump(payload))
			} else if eventType == 4 {
				event := events.GetsocknameEvent{}
				event.Decode(payload)

				fmt.Printf("%s[GetsocknameEvent]%s PID: %d, TID: %d, FD: %d, %s\n", cyan, reset, event.PID, event.TID, event.FD, event.Addr())
				outputChan <- &event
			} else if eventType == 5 {
				event := events.ForkEvent{}
				event.Decode(payload)

				fmt.Printf("%s[ForkEvent]%s PID: %d, ChildPID: %d\n", cyan, reset, event.PID, event.ChildPID)
				outputChan <- &event
			}
		}
	}
}

func (stream *Stream) refreshPids() {
	interceptedProcs := map[uint32]docker.Proc{}
	interceptedContainers := map[string]docker.Container{}

	for {
		newInterceptedProcs := stream.containers.GetProcsToIntercept()
		newInterceptedContainers := stream.containers.GetContainersToIntercept()

		// Check for new procs
		for pid, newProc := range newInterceptedProcs {
			_, exists := interceptedProcs[pid]
			if !exists {
				interceptedProcs[pid] = newProc

				go stream.procOpened(newProc)
			}
		}

		// Check for closed procs
		for pid, oldProc := range interceptedProcs {
			_, exists := newInterceptedProcs[pid]
			if !exists {
				delete(interceptedProcs, pid)

				go stream.procClosed(oldProc)
			}
		}

		// Check for new containers
		for containerId, newContainer := range newInterceptedContainers {
			_, exists := interceptedContainers[containerId]
			if !exists {
				interceptedContainers[containerId] = newContainer

				go stream.containerOpened(newContainer)
			}
		}

		// Check for closed container
		for containerId, oldContainer := range interceptedContainers {
			_, exists := newInterceptedContainers[containerId]
			if !exists {
				delete(interceptedContainers, containerId)

				go stream.containerClosed(oldContainer)
			}
		}

		time.Sleep(containerPIDsRefreshRate)
	}
}

func (stream *Stream) containerOpened(container docker.Container) {
	fmt.Println("Container opened:", container.RootFSPath, "ID:", container.ID)

	if stream.cgroupMap != nil {
		// On some machines the cgroup name will be like: docker-7d15edd8496d92281ba0cae75a3e96f1a5aafbf0ebd37ece0499f0ab2f8cacf6.scope
		// on others it will be just the ID like: 7d15edd8496d92281ba0cae75a3e96f1a5aafbf0ebd37ece0499f0ab2f8cacf6
		cgroupName1 := fmt.Sprintf("docker-%s.scope", container.ID)
		key1 := djb2(cgroupName1)
		cgroupName2 := container.ID // important to copy-by-value
		key2 := djb2(cgroupName2)
		value := container.IP

		stream.cgroupMap.Update(unsafe.Pointer(&key1), unsafe.Pointer(&value))
		stream.cgroupMap.Update(unsafe.Pointer(&key2), unsafe.Pointer(&value))
	}
	stream.attachUprobesLibSSL(container)
}

func (stream *Stream) containerClosed(container docker.Container) {
	fmt.Println("Container closed:", container.RootFSPath)

	if stream.cgroupMap != nil {
		cgroupName1 := fmt.Sprintf("docker-%s.scope", container.ID)
		key1 := djb2(cgroupName1)
		cgroupName2 := container.ID // important to copy-by-value
		key2 := djb2(cgroupName2)

		stream.cgroupMap.DeleteKey(unsafe.Pointer(&key1))
		stream.cgroupMap.DeleteKey(unsafe.Pointer(&key2))
	}

	stream.probeManager.DetachUprobesForContainer(container)
}

func djb2(s string) uint64 {
	var hash uint64 = 5381

	for _, c := range s {
		hash = ((hash << 5) + hash) + uint64(c)
	}

	return hash
}

func (stream *Stream) procOpened(proc docker.Proc) {
	fmt.Println("Proc opened:", proc.PID, proc.ExecPath, "libSSL:", proc.LibSSLVersion)

	// Determine offsets for this PID and send them to ebpf
	fdOffset, err := go_offsets.GetStructMemberOffset(proc.ExecPath, "internal/poll.FD", "Sysfd")
	if err != nil {
		// Fail silently here because this is probably not a Go binary
		fdOffset = 16
	}
	// TODO: This should be the PID, otherwise at the moment, this wont work if executables from different versions of
	// Go are running if each version has a different offset
	key1 := uint32(0)
	value1 := offsets{goFdOffset: fdOffset}
	stream.goOffsetsMap.Update(unsafe.Pointer(&key1), unsafe.Pointer(&value1))

	// Send the libssl version for this PID's container to ebpf
	pid := proc.PID
	version := proc.LibSSLVersion
	stream.libSSLVersionsMap.Update(unsafe.Pointer(&pid), unsafe.Pointer(&version))

	// Attach uprobes to the proc (if it is a Go executable being run)
	stream.attachUprobesGo(proc)
}

func (stream *Stream) procClosed(proc docker.Proc) {
	fmt.Println("Proc closed:", proc.PID, proc.ExecPath)

	stream.probeManager.DetachUprobesForProc(proc)
}

func (stream *Stream) Close() {
	stream.interruptChan <- 1
	stream.probeManager.Close()
}

func (stream *Stream) attachProbes() {
	kprobes := map[string][]string{
		"sys_accept":      []string{"probe_accept4", "probe_ret_accept4"},
		"sys_accept4":     []string{"probe_accept4", "probe_ret_accept4"},
		"sys_connect":     []string{"probe_connect", "probe_ret_connect"},
		"sys_getsockname": []string{"probe_getsockname", "probe_ret_getsockname"},
		// TODO: Remove all the related to this kprobe once we're sure we dont need it
		// "sys_close":       []string{"probe_close", "probe_ret_close"},
		"sys_sendto":   []string{"probe_sendto", "probe_ret_sendto"},
		"sys_recvfrom": []string{"probe_recvfrom", "probe_ret_recvfrom"},
		"sys_write":    []string{"probe_write", "probe_ret_write"},
		"sys_read":     []string{"probe_read", "probe_ret_read"},
	}
	// These two are disabled because they are available on linuxkit (docker desktop for mac) kernel 6.6
	// security_socket_sendmsg & security_socket_recvmsg

	for sysFunc, probeFuncs := range kprobes {
		if len(probeFuncs) != 2 {
			fmt.Println(probeFuncs, len(probeFuncs))
			panic("must set entry & return kprobes")
		}

		funcName := fmt.Sprintf("__%s_%s", ksymArch(), sysFunc)
		err := stream.probeManager.AttachToKProbe(probeFuncs[0], funcName)
		if err != nil {
			panic(err)
		}
		err = stream.probeManager.AttachToKRetProbe(probeFuncs[1], funcName)
		if err != nil {
			panic(err)
		}
	}

	// Attach the process fork tracepoint
	err := stream.probeManager.AttachTracepoint("trace_sched_process_fork", "sched", "sched_process_fork")
	if err != nil {
		panic(err)
	}
}

func (stream *Stream) attachUprobesLibSSL(container docker.Container) {
	// TODO: Find where libssl is and also send the version to ebpf
	libSslPath := container.LibSSLPath
	fmt.Println("Attaching openssl uprobes to:", libSslPath)

	// Attach libssl uprobes
	uprobes := map[string][]string{
		"SSL_read":     []string{"probe_entry_SSL_read", "probe_ret_SSL_read"},
		"SSL_read_ex":  []string{"probe_entry_SSL_read_ex", "probe_ret_SSL_read_ex"},
		"SSL_write":    []string{"probe_entry_SSL_write", "probe_ret_SSL_write"},
		"SSL_write_ex": []string{"probe_entry_SSL_write_ex", "probe_ret_SSL_write_ex"},
	}
	// These two are disabled because they are available on linuxkit (docker desktop for mac) kernel 6.6
	// security_socket_sendmsg:
	// security_socket_recvmsg

	for funcName, probeFuncs := range uprobes {
		if len(probeFuncs) != 2 {
			fmt.Println(probeFuncs, len(probeFuncs))
			panic("must set entry+return kprobes")
		}

		_, err := stream.probeManager.AttachToUProbe(container, probeFuncs[0], funcName, libSslPath)
		if err != nil {
			fmt.Println("ERROR AttachToUProbe() for", probeFuncs[0], err)
		}
		if len(probeFuncs[1]) > 0 {
			_, err = stream.probeManager.AttachToURetProbe(container, probeFuncs[1], funcName, libSslPath)
			if err != nil {
				fmt.Println("ERROR AttachToUProbe() for", probeFuncs[1], err)
			}
		}
	}
}

func (stream *Stream) attachUprobesGo(proc docker.Proc) error {
	uprobes := map[string][]string{
		"crypto/tls.(*Conn).Write": []string{"probe_entry_go_tls_write", ""},
		"crypto/tls.(*Conn).Read":  []string{"probe_entry_go_tls_read", "probe_exit_go_tls_read"},
	}

	for funcName, probeFuncs := range uprobes {
		if len(probeFuncs) != 2 {
			fmt.Println(probeFuncs, len(probeFuncs))
			panic("must set entry+return kprobes")
		}

		err := stream.probeManager.AttachGoUProbes(proc, probeFuncs[0], probeFuncs[1], funcName)
		if err != nil {
			fmt.Println("Warning: failed to attach Go UProbes, probably not a Go binary.. msg:", err)
			return err
		}
		fmt.Println("Attached Go Uprobes for", funcName, proc.PID, proc.ExecPath)

	}
	return nil
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

func getEventType(payload []byte) int {
	var eventType uint64
	buf := bytes.NewBuffer(payload)
	if err := binary.Read(buf, binary.LittleEndian, &eventType); err != nil {
		return 0
	}

	return int(eventType)
}
