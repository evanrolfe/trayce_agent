package internal

import "fmt"

type SocketDesc struct {
	LocalAddr  string
	RemoteAddr string
	Protocol   string
	Pid        uint32
	Fd         uint32
}

func NewSocketDesc(Pid uint32, Fd uint32) *SocketDesc {
	m := &SocketDesc{Pid: Pid, Fd: Fd}
	return m
}

func (socket *SocketDesc) IsComplete() bool {
	return (socket.LocalAddr == "" || socket.RemoteAddr == "" || socket.Protocol == "")
}

func (socket *SocketDesc) Key() string {
	return fmt.Sprintf("%d-%d", socket.Pid, socket.Fd)
}
