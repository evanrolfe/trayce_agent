package models

import "fmt"

// SocketMap tracks sockets which have been observed in ebpf
type SocketMap map[string]*SocketDesc

func NewSocketMap() SocketMap {
	m := make(SocketMap)
	return m
}

func (m SocketMap) ProcessConnectEvent(event *ConnectEvent) *SocketDesc {
	socket, exists := m[event.Key()]
	if !exists {
		socket = NewSocketDesc(event.Pid, event.Fd)
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

func (m SocketMap) GetSocket(key string) (*SocketDesc, bool) {
	socket, exists := m[key]
	return socket, exists
}

func (m SocketMap) ProcessDataEvent(event *DataEvent) (SocketMsgI, error) {
	socket, exists := m.GetSocket(event.Key())

	if !exists {
		return nil, fmt.Errorf("no socket found")
	}

	socketMsg := socket.ProcessDataEvent(event)

	return socketMsg, nil
}

func (m SocketMap) ProcessCloseEvent(event *CloseEvent) {
	delete(m, event.Key())
}
