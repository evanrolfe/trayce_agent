package sockets

import "github.com/evanrolfe/dockerdog/internal/bpf_events"

type SocketI interface {
	ProcessDataEvent(event *bpf_events.DataEvent) *SocketMsg
	GetRemoteAddr() string
}
