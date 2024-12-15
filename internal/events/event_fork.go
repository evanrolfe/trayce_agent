package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ForkEvent is sent from ebpf when a process is forked to create a child process
type ForkEvent struct {
	EventType   uint64 `json:"eventType"`
	TimestampNs uint64 `json:"timestampNs"`
	PID         uint32 `json:"pid"`
	ChildPID    uint32 `json:"tid"`
}

func (de *ForkEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &de.EventType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.TimestampNs); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.ChildPID); err != nil {
		return
	}

	return nil
}

func (de *ForkEvent) Key() string {
	return fmt.Sprintf("%d-%d", de.PID, 0)
}
