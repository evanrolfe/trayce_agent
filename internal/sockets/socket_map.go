package sockets

import (
	"fmt"

	"github.com/evanrolfe/dockerdog/internal/bpf_events"
)

// SocketMap tracks sockets which have been observed in ebpf
type SocketMap map[string]SocketI

func NewSocketMap() SocketMap {
	m := make(SocketMap)
	return m
}

func (m SocketMap) GetSocket(key string) (SocketI, bool) {
	socket, exists := m[key]
	return socket, exists
}

func (m SocketMap) ProcessConnectEvent(event *bpf_events.ConnectEvent) SocketI {
	socket, exists := m[event.Key()]
	if !exists {
		// TODO: This should first create an SocketUnknown, then change it to SocketHttp11 once we can detect the protocol
		socket := NewSocketHttp11(event)
		m[event.Key()] = &socket
	}

	return socket
}

func (m SocketMap) ProcessDataEvent(event *bpf_events.DataEvent) (*Flow, error) {
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
