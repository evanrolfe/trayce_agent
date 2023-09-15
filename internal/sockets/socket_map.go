package sockets

import (
	"fmt"
	"sync"

	"github.com/evanrolfe/dockerdog/internal/bpf_events"
)

// SocketMap tracks sockets which have been observed in ebpf
type SocketMap struct {
	mu      sync.Mutex
	sockets map[string]SocketI
}

func NewSocketMap() *SocketMap {
	m := SocketMap{
		sockets: make(map[string]SocketI),
	}
	return &m
}

func (m *SocketMap) GetSocket(key string) (SocketI, bool) {
	socket, exists := m.sockets[key]
	return socket, exists
}

// func (m *SocketMap) SetSocket(key string) (SocketI, bool) {
// 	socket, exists := m.sockets[key]
// 	return socket, exists
// }

func (m *SocketMap) ProcessConnectEvent(event *bpf_events.ConnectEvent) SocketI {
	m.mu.Lock()
	// fmt.Println("[SocketMap] ProcessConnectEvent got a lock")
	defer m.mu.Unlock() // defer func() { fmt.Println("[SocketMap] ProcessConnectEvent releasing lock"); m.mu.Unlock() }()

	socket, exists := m.GetSocket(event.Key())

	if !exists {
		m.Debug()
		fmt.Println("[SocketMap] Connect - creating socket for:", event.Key())
		// TODO: This should first create an SocketUnknown, then change it to SocketHttp11 once we can detect the protocol
		socket := NewSocketHttp11(event)
		m.sockets[event.Key()] = &socket
		m.Debug()
	} else {
		fmt.Println("[SocketMap] Connect - found socket for:", event.Key())
		socket.ProcessConnectEvent(event)
	}

	return socket
}

func (m *SocketMap) ProcessDataEvent(event *bpf_events.DataEvent) (*Flow, error) {
	m.mu.Lock()
	// fmt.Println("[SocketMap] ProcessDataEvent got a lock")
	defer m.mu.Unlock() // defer func() { fmt.Println("[SocketMap] ProcessDataEvent releasing lock"); m.mu.Unlock() }()

	socket, exists := m.GetSocket(event.Key())
	var msg *Flow

	if !exists {
		m.Debug()
		fmt.Println("[SocketMap] DataEvent - creating socket for:", event.Key())
		socket := NewSocketHttp11FromData(event)
		msg = socket.ProcessDataEvent(event)
		m.sockets[event.Key()] = &socket
		m.Debug()
	} else {
		fmt.Println("[SocketMap] DataEvent - found socket for:", event.Key())
		msg = socket.ProcessDataEvent(event)
	}

	return msg, nil
}

func (m *SocketMap) ProcessCloseEvent(event *bpf_events.CloseEvent) {
	delete(m.sockets, event.Key())
}

func (m *SocketMap) Debug() {
	socketLine := ""
	for _, socket := range m.sockets {
		socketLine += ", " + socket.Key()
	}
	fmt.Println(socketLine)
}
