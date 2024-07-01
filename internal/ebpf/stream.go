package ebpf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/evanrolfe/trayce_agent/internal/docker"
	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/evanrolfe/trayce_agent/internal/go_offsets"
)

const (
	containerPIDsRefreshRateMs = 10
	// TODO: Make it search for this in multpile places:
	defaultLibSslPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	libSslPath1       = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"
)

// Stream is a bridge between the docker client and ebpf. When new containers and proccesses are opened, it instruments
// them with ebpf probes. It also provides an event stream channel which gives us the Connect,Data and Close events that
// are sent from ebpf.
type Stream struct {
	probeManager ProbeManagerI
	containers   ContainersI

	containerUProbes map[string][]*libbpfgo.BPFLink

	dataEventsBuf     *libbpfgo.RingBuffer
	pidsMap           *libbpfgo.BPFMap
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
	ReceiveEvents(mapName string, eventsChan chan []byte) error
	GetMap(mapName string) (*libbpfgo.BPFMap, error)
	AttachToUProbe(funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error)
	AttachToURetProbe(funcName string, probeFuncName string, binaryPath string) (*libbpfgo.BPFLink, error)
	DetachAllGoUProbes() error
	AttachGoUProbes(funcName string, exitFuncName string, probeFuncName string, proc docker.Proc) error
	DetachGoUProbes(probeFuncName string, binaryPath string, pid uint32) error
	Close()
}

type offsets struct {
	goFdOffset uint64
}

func NewStream(containers ContainersI, probeManager ProbeManagerI) *Stream {
	return &Stream{
		probeManager:     probeManager,
		containers:       containers,
		containerUProbes: map[string][]*libbpfgo.BPFLink{},
		interruptChan:    make(chan int),
		dataEventsChan:   make(chan []byte, 10000),
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
	// Attach Kprobes
	kprobes := map[string][]string{
		"sys_accept":   []string{"probe_accept4, probe_ret_accept4"},
		"sys_accept4":  []string{"probe_accept4, probe_ret_accept4"},
		"sys_connect":  []string{"probe_connect, probe_ret_connect"},
		"sys_close":    []string{"probe_close, probe_ret_close"},
		"sys_sendto":   []string{"probe_sendto, probe_ret_sendto"},
		"sys_recvfrom": []string{"probe_recvfrom, probe_ret_recvfrom"},
		"sys_write":    []string{"probe_write, probe_ret_write"},
		"sys_read":     []string{"probe_read, probe_ret_read"},
	}
	// These two are disabled because they are available on linuxkit (docker desktop for mac) kernel 6.6
	// security_socket_sendmsg:
	// security_socket_recvmsg

	for sysFunc, probeFuncs := range kprobes {
		if len(probeFuncs) != 2 {
			panic("must set entry+return kprobes")
		}
		funcName := fmt.Sprintf("__%s_%s", ksymArch(), sysFunc)
		err := stream.probeManager.AttachToKProbe("probe_read", funcName)
		if err != nil {
			panic(err)
		}
		err = stream.probeManager.AttachToKRetProbe("probe_ret_read", funcName)
		if err != nil {
			panic(err)
		}
	}

	// events.DataEvents ring buffer
	err := stream.probeManager.ReceiveEvents("data_events", stream.dataEventsChan)
	if err != nil {
		panic(err)
	}

	// Intercepted PIDs map
	pidsMap, err := stream.probeManager.GetMap("intercepted_pids")
	if err != nil {
		panic(err)
	}
	stream.pidsMap = pidsMap
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

				cyan := "\033[36m"
				reset := "\033[0m"

				// if event.Fd < 10 {
				// 	fmt.Println("[events.ConnectEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port, " local? ", event.Local)
				// }
				fmt.Println(string(cyan), "[events.ConnectEvent]", string(reset), " Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", remote: ", event.IPAddr(), ":", event.Port, " local IP: ", event.LocalIPAddr())
				// fmt.Print(hex.Dump(payload))

				socketInfo, err := getSocketInfo2(int(event.Pid), int(event.Fd))
				if err != nil {
					fmt.Printf("Error getting socket information: %v\n", err)
				}

				if err == nil {
					fmt.Println("----------> socketInfo:", socketInfo)
				}

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
					fmt.Println("\n[events.DataEvent] Received", event.DataLen, "bytes [ALL BLANK, DROPPING]")
					continue
				}
				// fmt.Println("\n[events.DataEvent] Received ", event.DataLen, "bytes, source:", event.Source(), ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, " ssl_ptr:", event.SslPtr)
				// fmt.Print(hex.Dump(event.PayloadTrimmed(256)))

				outputChan <- &event

			} else if eventType == 2 {
				event := events.CloseEvent{}
				event.Decode(payload)
				red := "\033[35m"
				reset := "\033[0m"

				fmt.Println(string(red), "[events.CloseEvent]", string(reset), " PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd)
				outputChan <- &event

				// DebugEvent
			} else if eventType == 3 {
				event := events.DebugEvent{}
				event.Decode(payload)
				fmt.Println("\n[DebugEvent] Received, PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, " - ", string(event.Payload()))
				fmt.Print(hex.Dump(payload))
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

		time.Sleep(containerPIDsRefreshRateMs * time.Millisecond)
	}
}

// This is causing the first test case to fail for some reason
func (stream *Stream) containerOpened(container docker.Container) {
	fmt.Println("Container opened:", container.RootFSPath)
	links := []*libbpfgo.BPFLink{}

	// TODO: Find where libssl is and also send the version to ebpf
	libSslPath := container.LibSSLPath
	fmt.Println("Attaching openssl uprobes to:", libSslPath)

	// uprobe/SSL_read
	// TODO: Handle errors
	link, _ := stream.probeManager.AttachToUProbe("probe_entry_SSL_read", "SSL_read", libSslPath)
	links = append(links, link)
	stream.probeManager.AttachToURetProbe("probe_ret_SSL_read", "SSL_read", libSslPath)
	links = append(links, link)

	// uprobe/SSL_read_ex
	link, _ = stream.probeManager.AttachToUProbe("probe_entry_SSL_read_ex", "SSL_read_ex", libSslPath)
	links = append(links, link)
	link, _ = stream.probeManager.AttachToURetProbe("probe_ret_SSL_read_ex", "SSL_read_ex", libSslPath)
	links = append(links, link)

	// uprobe/SSL_write
	link, _ = stream.probeManager.AttachToUProbe("probe_entry_SSL_write", "SSL_write", libSslPath)
	links = append(links, link)
	link, _ = stream.probeManager.AttachToURetProbe("probe_ret_SSL_write", "SSL_write", libSslPath)
	links = append(links, link)

	// uprobe/SSL_write_ex
	link, _ = stream.probeManager.AttachToUProbe("probe_entry_SSL_write_ex", "SSL_write_ex", libSslPath)
	links = append(links, link)
	link, _ = stream.probeManager.AttachToURetProbe("probe_ret_SSL_write_ex", "SSL_write_ex", libSslPath)
	links = append(links, link)

	// TODO: Move this logic to bpf_program.go
	stream.containerUProbes[container.Id] = links
}

func (stream *Stream) containerClosed(container docker.Container) {
	fmt.Println("Container closed:", container.RootFSPath)
	_, exists := stream.containerUProbes[container.Id]
	if !exists {
		fmt.Println("	No links found for", container.Id)
		return
	}
	for _, link := range stream.containerUProbes[container.Id] {
		fmt.Println("	Destroying BPFLink:", link)
		link.Destroy()
	}

	// TODO: This needs to dettach only the uprobes for this container
	stream.probeManager.DetachAllGoUProbes()
}

func (stream *Stream) procOpened(proc docker.Proc) {
	fmt.Println("Proc opened:", proc.Pid, proc.ExecPath, "libSSL:", proc.LibSSLVersion)
	// Send the intercepted PIDs to ebpf
	if stream.pidsMap != nil {
		// Imporant that we copy these two vars by value here:
		pid := proc.Pid
		ip := proc.Ip
		pidUnsafe := unsafe.Pointer(&pid)
		ipUnsafe := unsafe.Pointer(&ip)
		stream.pidsMap.Update(pidUnsafe, ipUnsafe)
	}

	// Determine offsets for this PID and send them to ebpf
	fdOffset, err := go_offsets.GetStructMemberOffset(proc.ExecPath, "internal/poll.FD", "Sysfd")
	if err != nil {
		fmt.Println("Error finding fdOffset:", err)
		fdOffset = 16
	}
	// TODO: This should be the PID, otherwise at the moment, this wont work if executables from different versions of
	// Go are running if each version has a different offset
	key1 := uint32(0)
	value1 := offsets{goFdOffset: fdOffset}
	key1Unsafe := unsafe.Pointer(&key1)
	value1Unsafe := unsafe.Pointer(&value1)
	stream.goOffsetsMap.Update(key1Unsafe, value1Unsafe)

	// Send the libssl version for this PID's container to ebpf
	pid := proc.Pid
	version := proc.LibSSLVersion
	pidUnsafe := unsafe.Pointer(&pid)
	versionUnsafe := unsafe.Pointer(&version)
	stream.libSSLVersionsMap.Update(pidUnsafe, versionUnsafe)

	// Attach uprobes to the proc (if it is a Go executable being run)
	err = stream.probeManager.AttachGoUProbes("probe_entry_go_tls_write", "", "crypto/tls.(*Conn).Write", proc)
	if err != nil {
		fmt.Println("Error bpfProg.AttachGoUProbes() write:", err)
		return
	}
	fmt.Println("Attached Go Uprobes for crypto/tls.(*Conn).Write", proc.Pid, proc.ExecPath)

	err = stream.probeManager.AttachGoUProbes("probe_entry_go_tls_read", "probe_exit_go_tls_read", "crypto/tls.(*Conn).Read", proc)
	if err != nil {
		fmt.Println("Error bpfProg.AttachGoUProbes() read:", err)
		return
	}
	fmt.Println("Attached Go Uprobes for crypto/tls.(*Conn).Read", proc.Pid, proc.ExecPath)
}

func (stream *Stream) procClosed(proc docker.Proc) {
	fmt.Println("Proc closed:", proc.Pid, proc.ExecPath)

	// Delete the intercepted PIDs from ebpf map
	if stream.pidsMap != nil {
		// Imporant that we copy these two vars by value here:
		pid := proc.Pid
		pidUnsafe := unsafe.Pointer(&pid)
		stream.pidsMap.DeleteKey(pidUnsafe)
	}

	stream.probeManager.DetachGoUProbes("crypto/tls.(*Conn).Write", proc.ExecPath, proc.Pid)
	stream.probeManager.DetachGoUProbes("crypto/tls.(*Conn).Read", proc.ExecPath, proc.Pid)
}

func (stream *Stream) Close() {
	stream.interruptChan <- 1
	stream.probeManager.Close()
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

func getSocketInfo(pid, fd int) (string, error) {
	// Build the path to the symbolic link for the file descriptor
	fdPath := filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(fd))
	fmt.Println(fdPath)
	// Use syscall.Exec to execute readlink command
	cmd := exec.Command("readlink", fdPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error running readlink: %v", err)
	}

	return string(output), nil
}

func getSocketInfo2(pid, fd int) (string, error) {
	// Build the path to the symbolic link for the file descriptor
	fdPath := filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(fd))

	// Read the symbolic link
	link, err := os.Readlink(fdPath)
	if err != nil {
		return "", fmt.Errorf("error reading symbolic link: %v", err)
	}

	return link, nil
}

func parseSocketInfo(link string) (string, string, error) {
	// Extract local and remote addresses and ports from the symbolic link
	// The symbolic link format is usually like "socket:[inode]"
	parts := strings.Split(link, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("unexpected symbolic link format: %s", link)
	}

	inode := parts[1]

	// You may need to parse the inode to get further details if necessary
	return inode, "", nil
}
