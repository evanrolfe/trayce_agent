package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// CloseEvent is sent from ebpf when a socket is closed, see corresponding: struct close_event_t
type CloseEvent struct {
	EventType   uint64 `json:"eventType"`
	TimestampNs uint64 `json:"timestampNs"`
	Pid         uint32 `json:"pid"`
	Tid         uint32 `json:"tid"`
	Fd          uint32 `json:"fd"`
}

func (ce *CloseEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ce.EventType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.TimestampNs); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Fd); err != nil {
		return
	}

	return nil
}

func (ce *CloseEvent) Key() string {
	return fmt.Sprintf("%d-%d", ce.Pid, ce.Fd)
}
