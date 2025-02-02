package sockets

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/evanrolfe/trayce_agent/internal/events"
)

// SocketMap tracks sockets which have been observed in ebpf
type SocketMap struct {
	mu            sync.Mutex
	sockets       map[string]SocketI
	flowCallbacks []func(Flow)
}

func NewSocketMap() *SocketMap {
	m := SocketMap{
		sockets: make(map[string]SocketI),
	}
	return &m
}

func (m *SocketMap) AddFlowCallback(callback func(Flow)) {
	m.flowCallbacks = append(m.flowCallbacks, callback)
}

func (m *SocketMap) ProcessConnectEvent(event events.ConnectEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	socket, exists := m.getSocket(event.Key())

	if !exists {
		fmt.Println("[SocketMap] Connect - creating socket for:", event.Key())
		// TODO: This should first create an SocketUnknown, then change it to SocketHttp11 once we can detect the protocol
		socket := NewSocketUnknown(&event)
		m.setSocket(&socket)
	} else {
		fmt.Println("[SocketMap] Connect - found socket for:", event.Key())
		socket.ProcessConnectEvent(&event)
	}
}

func (m *SocketMap) ProcessGetsocknameEvent(event events.GetsocknameEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	socket, exists := m.getSocket(event.Key())
	if !exists {
		return
	}
	socket.ProcessGetsocknameEvent(&event)
}

func (m *SocketMap) ProcessForkEvent(event events.ForkEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// When a process is forked, all open connections are copied over to the the child process, so we need to do
	// the same thing here in the socket map
	for _, socket := range m.sockets {
		if socket.GetPID() == event.PID {
			newSocket := socket.Clone()
			newSocket.SetPID(event.ChildPID)
			m.sockets[newSocket.Key()] = newSocket
		}
	}
}

func (m *SocketMap) ProcessDataEvent(event events.DataEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	green := "\033[92m"
	reset := "\033[0m"
	fmt.Println(string(green), "[DataEvent]", string(reset), event.DataLen, "bytes, source:", event.Source(), ", PID:", event.PID, ", TID:", event.TID, "FD:", event.FD, ", cgroup:", event.CGroupName())
	fmt.Print(hex.Dump(event.Payload()))

	var socket SocketI
	socket, exists := m.getSocket(event.Key())
	if !exists {
		fmt.Println("[SocketMap] DataEvent no socket found, dropping.")
		return
	}

	// If the socket is unknown, try to detect the protocol, if no protocol is detected then drop the event.
	// Otherwise if a protocol is detected then convert it to the protocol socket
	unkownSocket, isUnknown := socket.(*SocketUnknown)
	if isUnknown {
		prevDataevent := unkownSocket.GetPrevDataEvent()
		prevData := []byte{}
		if prevDataevent != nil {
			prevData = prevDataevent.Payload()
		}
		protocol := detectProtocol(event.Payload(), prevData)
		fmt.Println("[SocketMap] detected protocol:", protocol)
		unkownSocket.SetPrevDataEvent(&event)

		switch protocol {
		case Unknown:
			return
		case HTTP:
			newSocket := NewSocketHttp11FromUnknown(unkownSocket)
			m.setSocket(&newSocket)
			socket = &newSocket
		case HTTP2:
			newSocket := NewSocketHttp2FromUnknown(unkownSocket)
			m.setSocket(&newSocket)
			socket = &newSocket
		case PSQL:
			newSocket := NewSocketPsqlFromUnknown(unkownSocket)
			m.setSocket(&newSocket)
			socket = &newSocket
		case MySQL:
			newSocket := NewSocketMysqlFromUnknown(unkownSocket)
			m.setSocket(&newSocket)
			socket = &newSocket
			// still need the previous event for mysql only
			socket.ProcessDataEvent(prevDataevent)
		}
	}

	socket.ProcessDataEvent(&event)
}

func (m *SocketMap) ProcessCloseEvent(event events.CloseEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, exists := m.getSocket(event.Key())
	if exists {
		fmt.Println("[SocketMap] CloseEvent - deleting socket for:", event.Key())
		delete(m.sockets, event.Key())
	}
}

func (m *SocketMap) Debug() {
	socketLine := ""
	for _, socket := range m.sockets {
		socketLine += socket.Key() + ", "
	}
	fmt.Println(socketLine)
}

func (m *SocketMap) getSocket(key string) (SocketI, bool) {
	socket, exists := m.sockets[key]
	return socket, exists
}

func (m *SocketMap) setSocket(socket SocketI) {
	socket.AddFlowCallback(func(flow Flow) {
		for _, callback := range m.flowCallbacks {
			callback(flow)
		}
	})

	m.sockets[socket.Key()] = socket
}
