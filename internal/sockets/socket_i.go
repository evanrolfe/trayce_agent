package sockets

import (
	"github.com/evanrolfe/trayce_agent/internal/events"
)

type SocketI interface {
	Key() string
	AddFlowCallback(callback func(Flow))
	ProcessConnectEvent(event *events.ConnectEvent)
	ProcessDataEvent(event *events.DataEvent)
	ProcessGetsocknameEvent(event *events.GetsocknameEvent)
	Clear()
}
