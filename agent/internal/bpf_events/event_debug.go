package bpf_events

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// CloseEvent is sent from ebpf when a socket is closed, see corresponding: struct close_event_t
type DebugEvent struct {
	EventType   uint64    `json:"eventType"`
	TimestampNs uint64    `json:"timestampNs"`
	Pid         uint32    `json:"pid"`
	Tid         uint32    `json:"tid"`
	Fd          uint32    `json:"fd"`
	DataLen     int32     `json:"dataLen"`
	Data        [300]byte `json:"data"`
}

func (de *DebugEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &de.EventType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.TimestampNs); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.Fd); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.DataLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.Data); err != nil {
		return
	}

	return nil
}

func (de *DebugEvent) Key() string {
	return fmt.Sprintf("%d-%d", de.Pid, de.Fd)
}

func (de *DebugEvent) Payload() []byte {
	return de.Data[:de.DataLen]
}
