package sockets

import (
	"github.com/evanrolfe/trayce_agent/internal/events"
)

type SocketI interface {
	Key() string
	GetPID() uint32
	SetPID(pid uint32)
	Clone() SocketI
	AddFlowCallback(callback func(Flow))
	ProcessDataEvent(event *events.DataEvent)
	Clear()
}
