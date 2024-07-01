package events

type EventType uint8

const (
	// EventTypeOutput upload to server or write to logfile.
	EventTypeOutput EventType = iota

	// EventTypeModuleData set as module cache data
	EventTypeModuleData

	// EventTypeEventProcessor display by event_processor.
	EventTypeEventProcessor
)

type IEvent interface {
	Key() string
}
