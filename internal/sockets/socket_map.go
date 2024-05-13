package sockets

import (
	"fmt"
	"sync"

	"github.com/evanrolfe/trayce_agent/internal/bpf_events"
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

func (m *SocketMap) GetSocket(key string) (SocketI, bool) {
	socket, exists := m.sockets[key]
	return socket, exists
}

func (m *SocketMap) SetSocket(socket SocketI) {
	socket.AddFlowCallback(func(flow Flow) {
		for _, callback := range m.flowCallbacks {
			callback(flow)
		}
	})

	m.sockets[socket.Key()] = socket
}

func (m *SocketMap) AddFlowCallback(callback func(Flow)) {
	m.flowCallbacks = append(m.flowCallbacks, callback)
}

func (m *SocketMap) ProcessConnectEvent(event bpf_events.ConnectEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	socket, exists := m.GetSocket(event.Key())

	if !exists {
		fmt.Println("[SocketMap] Connect - creating socket for:", event.Key())
		// TODO: This should first create an SocketUnknown, then change it to SocketHttp11 once we can detect the protocol
		socket := NewSocketUnknown(&event)
		m.SetSocket(&socket)
	} else {
		fmt.Println("[SocketMap] Connect - found socket for:", event.Key())
		socket.ProcessConnectEvent(&event)
	}
}

func (m *SocketMap) ProcessDataEvent(event bpf_events.DataEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var socket SocketI
	if event.Fd == 0 {
		// For some reason HTTPS request to ruby never have the FD value set, so in this case we just pick the last open socket
		keys := []string{}
		for key := range m.sockets {
			keys = append(keys, key)
		}

		// TODO: It needs to be investigated if this can happen with ruby, multiple open sockets in the same thread. If it can
		// happen then this will be an issue because we won't know which open socket to chose from.
		// See openssl_uprobes.h "workaround" comment for more details and also NOTES.md
		if len(keys) != 1 {
			fmt.Println("ERROR: wrong num of open sockets found for 0 FD request:\n", keys)
			return
		}

		socket = m.sockets[keys[0]]

	} else {
		var exists bool
		socket, exists = m.GetSocket(event.Key())

		if !exists {
			fmt.Println("[SocketMap] not socket found for event")
			return
		}
	}

	// fmt.Println("[SocketMap] DataEvent - found socket for:", event.Key(), "/", event.Rand)

	// If the socket is unknown, try to detect the protocol, if not detection then drop
	// but if detected then convert it to the protocol socket
	unkownSocket, isUnknown := socket.(*SocketUnknown)
	if isUnknown {
		protocol := detectProtocol(event.Payload())
		fmt.Println("[SocketMap] detected protocol:", protocol)
		switch protocol {
		case Unknown:
			return
		case HTTP:
			newSocket := NewSocketHttp11FromUnknown(unkownSocket)
			m.SetSocket(&newSocket)
			socket = &newSocket
		case HTTP2:
			newSocket := NewSocketHttp2FromUnknown(unkownSocket)
			m.SetSocket(&newSocket)
			socket = &newSocket
		}
	}

	socket.ProcessDataEvent(&event)
}

func (m *SocketMap) ProcessCloseEvent(event bpf_events.CloseEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Println("[SocketMap] CloseEvent - deleting socket for:", event.Key())
	delete(m.sockets, event.Key())
}

func (m *SocketMap) Debug() {
	socketLine := ""
	for _, socket := range m.sockets {
		socketLine += socket.Key() + ", "
	}
	fmt.Println(socketLine)
}
