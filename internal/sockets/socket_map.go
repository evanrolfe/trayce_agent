package sockets

import (
	"fmt"
	"sync"

	"github.com/evanrolfe/trayce_agent/internal/config"
	"github.com/evanrolfe/trayce_agent/internal/events"
)

// SocketMap tracks sockets which have been observed in ebpf
type SocketMap struct {
	mu            sync.Mutex
	sockets       map[string]Socket
	flowCallbacks []func(Flow)
	config        config.Config
}

func NewSocketMap(cfg config.Config) *SocketMap {
	m := SocketMap{
		sockets: make(map[string]Socket),
		config:  cfg,
	}
	return &m
}

func (m *SocketMap) AddFlowCallback(callback func(Flow)) {
	m.flowCallbacks = append(m.flowCallbacks, callback)
}

func (m *SocketMap) ProcessDataEvent(event events.DataEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Println(event.LogLine(m.config.Verbose))

	var socket Socket
	socket, exists := m.getSocket(event.Key())
	if !exists {
		fmt.Println("[SocketMap] DataEvent no socket found, creating new one...", event.Key())
		s := NewSocketUnknownFromData(&event)
		socket = &s
		m.setSocket(event.Key(), socket)
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
			m.setSocket(event.Key(), &newSocket)
			socket = &newSocket
		case HTTP2:
			newSocket := NewSocketHttp2FromUnknown(unkownSocket)
			m.setSocket(event.Key(), &newSocket)
			socket = &newSocket
		case PSQL:
			newSocket := NewSocketPsqlFromUnknown(unkownSocket)
			m.setSocket(event.Key(), &newSocket)
			socket = &newSocket
		case MySQL:
			newSocket := NewSocketMysqlFromUnknown(unkownSocket)
			m.setSocket(event.Key(), &newSocket)
			socket = &newSocket
			// still need the previous event for mysql, if it sends the header packet in a separate message from the payload
			if prevDataevent != nil && prevDataevent.DataLen == 4 {
				socket.ProcessDataEvent(prevDataevent)
			}
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

func (m *SocketMap) getSocket(key string) (Socket, bool) {
	socket, exists := m.sockets[key]
	return socket, exists
}

func (m *SocketMap) setSocket(key string, socket Socket) {
	socket.AddFlowCallback(func(flow Flow) {
		for _, callback := range m.flowCallbacks {
			callback(flow)
		}
	})

	m.sockets[key] = socket
}
