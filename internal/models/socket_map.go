package models

import "fmt"

type SocketMap map[string]*SocketDesc

func NewSocketMap() SocketMap {
	m := make(SocketMap)
	return m
}

func (m SocketMap) ParseAddrEvent(event *SocketAddrEvent) *SocketDesc {
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

func (m SocketMap) AddProtocol() {

}

func (m SocketMap) Debug() {
	fmt.Println("-------------------------------------------------------------\nSockets:")
	for key, value := range m {
		fmt.Printf("	%s => {Src: %s, Dst: %s, %s}\n", key, value.LocalAddr, value.RemoteAddr, value.Protocol)
	}
}
