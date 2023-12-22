package bpf_events

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
	"github.com/evanrolfe/dockerdog/internal/docker"
	"github.com/evanrolfe/dockerdog/internal/go_offsets"
)

const (
	bufPollRateMs              = 50
	containerPIDsRefreshRateMs = 5
	// TODO: Make it search for this in multpile places:
	defaultLibSslPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	libSslPath1       = "/usr/lib/x86_64-linux-gnu/libssl.so.1.1"
)

type Stream struct {
	bpfProg    *BPFProgram
	containers *docker.Containers

	dataEventsBuf     *libbpfgo.RingBuffer
	pidsMap           *libbpfgo.BPFMap
	goOffsetsMap      *libbpfgo.BPFMap
	libSSLVersionsMap *libbpfgo.BPFMap
	dataEventsChan    chan []byte
	interruptChan     chan int

	connectCallbacks []func(ConnectEvent)
	dataCallbacks    []func(DataEvent)
	closeCallbacks   []func(CloseEvent)
}

type offsets struct {
	goFdOffset uint64
}

func NewStream(containers *docker.Containers, bpfBytes []byte, btfFilePath string, libSslPath string) *Stream {
	bpfProg, err := NewBPFProgramFromBytes(bpfBytes, btfFilePath, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// kprobe/accept
	funcName := fmt.Sprintf("__%s_sys_accept4", ksymArch())
	bpfProg.AttachToKProbe("probe_accept4", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_accept4", funcName)

	// kprobe/connect
	funcName = fmt.Sprintf("__%s_sys_connect", ksymArch())
	bpfProg.AttachToKProbe("probe_connect", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_connect", funcName)

	// kprobe/close
	funcName = fmt.Sprintf("__%s_sys_close", ksymArch())
	bpfProg.AttachToKProbe("probe_close", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_close", funcName)

	// kprobe/sendto
	funcName = fmt.Sprintf("__%s_sys_sendto", ksymArch())
	bpfProg.AttachToKProbe("probe_sendto", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_sendto", funcName)

	// kprobe/recvfrom
	funcName = fmt.Sprintf("__%s_sys_recvfrom", ksymArch())
	bpfProg.AttachToKProbe("probe_recvfrom", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_recvfrom", funcName)

	// kprobe write
	funcName = fmt.Sprintf("__%s_sys_write", ksymArch())
	bpfProg.AttachToKProbe("probe_write", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_write", funcName)

	// kprobe read
	funcName = fmt.Sprintf("__%s_sys_read", ksymArch())
	bpfProg.AttachToKProbe("probe_read", funcName)
	bpfProg.AttachToKRetProbe("probe_ret_read", funcName)

	// kprobe security_socket_sendmsg
	bpfProg.AttachToKProbe("probe_entry_security_socket_sendmsg", "security_socket_sendmsg")

	// kprobe security_socket_recvmsg
	bpfProg.AttachToKProbe("probe_entry_security_socket_recvmsg", "security_socket_recvmsg")

	return &Stream{
		bpfProg:        bpfProg,
		containers:     containers,
		interruptChan:  make(chan int),
		dataEventsChan: make(chan []byte, 10000),
	}
}

func (stream *Stream) AddConnectCallback(callback func(ConnectEvent)) {
	stream.connectCallbacks = append(stream.connectCallbacks, callback)
}

func (stream *Stream) AddDataCallback(callback func(DataEvent)) {
	stream.dataCallbacks = append(stream.dataCallbacks, callback)
}

func (stream *Stream) AddCloseCallback(callback func(CloseEvent)) {
	stream.closeCallbacks = append(stream.closeCallbacks, callback)
}

func (stream *Stream) Start(outputChan chan IEvent) {
	// DataEvents ring buffer
	var err error
	stream.dataEventsBuf, err = stream.bpfProg.BpfModule.InitRingBuf("data_events", stream.dataEventsChan)
	if err != nil {
		panic(err)
	}
	stream.dataEventsBuf.Poll(bufPollRateMs)

	// Intercepted PIDs map
	pidsMap, err := stream.bpfProg.BpfModule.GetMap("intercepted_pids")
	if err != nil {
		panic(err)
	}
	stream.pidsMap = pidsMap
	go stream.refreshPids()

	// Offsets map
	goOffsetsMap, err := stream.bpfProg.BpfModule.GetMap("offsets_map")
	if err != nil {
		panic(err)
	}
	stream.goOffsetsMap = goOffsetsMap

	// libssl versions map
	libSSLVersionsMap, err := stream.bpfProg.BpfModule.GetMap("libssl_versions_map")
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

			// ConnectEvent
			if eventType == 0 {
				event := ConnectEvent{}
				event.Decode(payload)

				// if event.Fd < 10 {
				// 	fmt.Println("[ConnectEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", ", event.IPAddr(), ":", event.Port, " local? ", event.Local)
				// }
				fmt.Println("\n[ConnectEvent] Received ", len(payload), "bytes", "PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, ", remote: ", event.IPAddr(), ":", event.Port, " local IP: ", event.LocalIPAddr())
				fmt.Print(hex.Dump(payload))

				socketInfo, err := getSocketInfo2(int(event.Pid), int(event.Fd))
				if err != nil {
					fmt.Printf("Error getting socket information: %v\n", err)
				}

				if err == nil {
					fmt.Println("----------> socketInfo:", socketInfo)
				}

				outputChan <- &event

				// DataEvent
			} else if eventType == 1 {
				event := DataEvent{}
				err = event.Decode(payload)
				if err != nil {
					fmt.Println("[ERROR] failed to decode")
					panic(err)
				}
				if event.IsBlank() {
					fmt.Println("\n[DataEvent] Received", event.DataLen, "bytes [ALL BLANK, DROPPING]")
					continue
				}
				fmt.Println("\n[DataEvent] Received ", event.DataLen, "bytes, source:", event.Source(), ", PID:", event.Pid, ", TID:", event.Tid, "FD: ", event.Fd, " rand:", event.Rand)
				fmt.Print(hex.Dump(event.PayloadTrimmed(256)))

				outputChan <- &event

				// DebugEvent
			} else if eventType == 3 {
				event := DebugEvent{}
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

				stream.procClosed(oldProc)
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

				stream.containerClosed(oldContainer)
			}
		}

		time.Sleep(containerPIDsRefreshRateMs * time.Millisecond)
	}
}

// This is causing the first test case to fail for some reason
func (stream *Stream) containerOpened(container docker.Container) {
	fmt.Println("Container opened:", container.RootFSPath)

	// TODO: Find where libssl is and also send the version to ebpf

	libSslPath := container.LibSSLPath
	fmt.Println("Attaching uprobes to:", libSslPath)

	// uprobe/SSL_read
	stream.bpfProg.AttachToUProbe("probe_entry_SSL_read", "SSL_read", libSslPath)
	stream.bpfProg.AttachToURetProbe("probe_ret_SSL_read", "SSL_read", libSslPath)

	// uprobe/SSL_read_ex
	stream.bpfProg.AttachToUProbe("probe_entry_SSL_read_ex", "SSL_read_ex", libSslPath)
	stream.bpfProg.AttachToURetProbe("probe_ret_SSL_read_ex", "SSL_read_ex", libSslPath)

	// uprobe/SSL_write
	stream.bpfProg.AttachToUProbe("probe_entry_SSL_write", "SSL_write", libSslPath)
	stream.bpfProg.AttachToURetProbe("probe_ret_SSL_write", "SSL_write", libSslPath)

	// uprobe/SSL_write_ex
	stream.bpfProg.AttachToUProbe("probe_entry_SSL_write_ex", "SSL_write_ex", libSslPath)
	stream.bpfProg.AttachToURetProbe("probe_ret_SSL_write_ex", "SSL_write_ex", libSslPath)
}

func (stream *Stream) containerClosed(container docker.Container) {
	fmt.Println("Container closed:", container.RootFSPath)
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
	fmt.Println("Proc attaching Go Uprobes", proc.Pid, proc.ExecPath)
	err = stream.bpfProg.AttachGoUProbes("probe_entry_go_tls_write", "", "crypto/tls.(*Conn).Write", proc.ExecPath)
	if err != nil {
		fmt.Println("Error bpfProg.AttachGoUProbes() write:", err)
	}
	err = stream.bpfProg.AttachGoUProbes("probe_entry_go_tls_read", "probe_exit_go_tls_read", "crypto/tls.(*Conn).Read", proc.ExecPath)
	if err != nil {
		fmt.Println("Error bpfProg.AttachGoUProbes() read:", err)
	}
}

func (stream *Stream) procClosed(proc docker.Proc) {
	fmt.Println("Proc closed:", proc.Pid, proc.ExecPath)
	// For the moment we are not detaching the uprobes, it causes some issues and I'm not sure if there is actually any
	// benefit to detaching them
	// stream.bpfProg.DetachGoUProbes("crypto/tls.(*Conn).Write", proc.ExecPath)
	// stream.bpfProg.DetachGoUProbes("crypto/tls.(*Conn).Read", proc.ExecPath)
}

func (stream *Stream) Close() {
	stream.interruptChan <- 1
	stream.bpfProg.Close()
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
