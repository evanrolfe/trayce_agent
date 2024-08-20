package events

import "bytes"

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

func convertByteArrayToString(b [128]byte) string {
	// Find the null terminator or the end of the array
	n := bytes.IndexByte(b[:], 0)
	if n == -1 {
		// No null terminator found, use the entire array
		n = len(b)
	}
	return string(b[:n])
}
