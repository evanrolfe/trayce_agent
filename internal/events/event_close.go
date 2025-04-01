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
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	FD          uint32 `json:"fd"`
	SourceHost  uint32 `json:"source_host"`
	DestHost    uint32 `json:"dest_host"`
	SourcePort  uint16 `json:"source_port"`
	DestPort    uint16 `json:"dest_port"`
}

func (ce *CloseEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ce.EventType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.TimestampNs); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.TID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.FD); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.SourceHost); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.DestHost); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.SourcePort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.DestPort); err != nil {
		return
	}

	return nil
}

func (ce *CloseEvent) Key() string {
	return ce.Address()
}

func (ce *CloseEvent) Address() string {
	return fmt.Sprintf("%s:%d->%s:%d", intToIP(ce.SourceHost), ce.SourcePort, intToIP(ce.DestHost), ce.DestPort)
}

func (ce *CloseEvent) SourceAddr() string {
	return fmt.Sprintf("%s:%d", intToIP(ce.SourceHost), ce.SourcePort)
}

func (ce *CloseEvent) DestAddr() string {
	return fmt.Sprintf("%s:%d", intToIP(ce.DestHost), ce.DestPort)
}
