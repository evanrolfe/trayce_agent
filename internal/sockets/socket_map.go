package sockets

import (
	"fmt"

	"github.com/evanrolfe/dockerdog/internal/bpf_events"
)

// SocketMap tracks sockets which have been observed in ebpf
type SocketMap map[string]*SocketHttp11

func NewSocketMap() SocketMap {
	m := make(SocketMap)
	return m
}

func (m SocketMap) ProcessConnectEvent(event *bpf_events.ConnectEvent) *SocketHttp11 {
	socket, exists := m[event.Key()]
	if !exists {
		socket = NewSocketHttp11(event.Pid, event.Fd)
		m[event.Key()] = socket
	}

	addr := fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)

	if event.Local && socket.LocalAddr == "" {
		socket.LocalAddr = addr
	} else if !event.Local && socket.RemoteAddr == "" {
		socket.RemoteAddr = addr
	}

	return socket
}

func (m SocketMap) GetSocket(key string) (*SocketHttp11, bool) {
	socket, exists := m[key]
	return socket, exists
}

func (m SocketMap) ProcessDataEvent(event *bpf_events.DataEvent) (*SocketMsg, error) {
	socket, exists := m.GetSocket(event.Key())

	if !exists {
		return nil, fmt.Errorf("no socket found")
	}

	msg := socket.ProcessDataEvent(event)

	return msg, nil
}

func (m SocketMap) ProcessCloseEvent(event *bpf_events.CloseEvent) {
	delete(m, event.Key())
}
