package sockets

import "github.com/evanrolfe/dockerdog/internal/bpf_events"

type SocketI interface {
	ProcessConnectEvent(event *bpf_events.ConnectEvent)
	ProcessDataEvent(event *bpf_events.DataEvent) *Flow
	Key() string
}
