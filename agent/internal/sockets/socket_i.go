package sockets

import "github.com/evanrolfe/dockerdog/internal/bpf_events"

type SocketI interface {
	Key() string
	AddFlowCallback(callback func(Flow))
	ProcessConnectEvent(event *bpf_events.ConnectEvent)
	ProcessDataEvent(event *bpf_events.DataEvent)
	Clear()
}