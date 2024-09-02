package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// CloseEvent is sent from ebpf when a socket is closed, see corresponding: struct close_event_t
type GetsocknameEvent struct {
	EventType   uint64 `json:"eventType"`
	TimestampNs uint64 `json:"timestampNs"`
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	FD          uint32 `json:"fd"`
	Host        uint32 `json:"host"`
	Port        uint16 `json:"port"`
}

func (de *GetsocknameEvent) Decode(payload []byte) (err error) {
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
	if err = binary.Read(buf, binary.LittleEndian, &de.TID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.FD); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &de.Host); err != nil {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &de.Port); err != nil {
		return
	}

	return nil
}

func (de *GetsocknameEvent) Key() string {
	return fmt.Sprintf("%d-%d", de.PID, de.FD)
}

func (de *GetsocknameEvent) Addr() string {
	host := uint32ToIP(de.Host).String()
	return fmt.Sprintf("%s:%d", host, de.Port)
}
