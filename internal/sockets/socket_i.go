package sockets

import (
	"github.com/evanrolfe/trayce_agent/internal/events"
)

type SocketI interface {
	Key() string
	AddFlowCallback(callback func(Flow))
	ProcessDataEvent(event *events.DataEvent)
}
