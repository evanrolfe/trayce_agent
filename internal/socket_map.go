package internal

import "fmt"

type SocketDesc struct {
	SourceAddr string
	DestAddr   string
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
		socket.SourceAddr = addr
	} else {
		socket.DestAddr = addr
	}
}

func (m *SocketMap) AddProtocol() {

}

func (m SocketMap) Debug() {
	fmt.Println("-------------------------------------------------------------\nSockets:")
	for key, value := range m {
		fmt.Printf("	%s => {Src: %s, Dst: %s, %s}\n", key, value.SourceAddr, value.DestAddr, value.Protocol)
	}
}
