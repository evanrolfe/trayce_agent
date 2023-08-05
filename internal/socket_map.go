package internal

import "fmt"

type SocketDesc struct {
	LocalAddr  string
	RemoteAddr string
	Protocol   string
}

type SocketMap map[string]*SocketDesc

func NewSocketMap() SocketMap {
	m := make(SocketMap)
	return m
}

func (m SocketMap) ParseAddrEvent(event *SocketAddrEvent) {
	socket, exists := m[event.Key()]
	if !exists {
		socket = &SocketDesc{}
		m[event.Key()] = socket
	}

	addr := fmt.Sprintf("%s:%d", event.IPAddr(), event.Port)

	if event.Local {
		socket.LocalAddr = addr
	} else {
		socket.RemoteAddr = addr
	}
}

func (m *SocketMap) AddProtocol() {

}

func (m SocketMap) Debug() {
	fmt.Println("-------------------------------------------------------------\nSockets:")
	for key, value := range m {
		fmt.Printf("	%s => {Src: %s, Dst: %s, %s}\n", key, value.LocalAddr, value.RemoteAddr, value.Protocol)
	}
}
