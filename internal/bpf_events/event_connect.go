package bpf_events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// ConnectEvent is sent from ebpf when a socket is connected, see corresponding: struct connect_event_t
type ConnectEvent struct {
	EventType   uint64 `json:"eventType"`
	TimestampNs uint64 `json:"timestampNs"`
	Pid         uint32 `json:"pid"`
	Tid         uint32 `json:"tid"`
	Fd          uint32 `json:"fd"`
	Ip          uint32 `json:"ip"`
	Port        uint16 `json:"port"`
	Local       bool   `json:"local"`
}

func (ce *ConnectEvent) Decode(payload []byte) (err error) {
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
	if err = binary.Read(buf, binary.BigEndian, &ce.Ip); err != nil {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &ce.Port); err != nil {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &ce.Local); err != nil {
		return
	}

	return nil
}

func (ce *ConnectEvent) IPAddr() string {
	ipBytes := make([]byte, 4)
	ipBytes[0] = byte(ce.Ip >> 24)
	ipBytes[1] = byte(ce.Ip >> 16)
	ipBytes[2] = byte(ce.Ip >> 8)
	ipBytes[3] = byte(ce.Ip)
	ipAddr := net.IP(ipBytes)

	return ipAddr.String()
}

func (ce *ConnectEvent) Key() string {
	return fmt.Sprintf("%d-%d", ce.Pid, ce.Fd)
}

// func (ce *ConnDataEvent) StringHex() string {
// 	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Addr: %s", ce.Pid, bytes.TrimSpace(ce.Comm[:]), ce.Tid, ce.Fd, ce.Addr)
// 	return s
// }

// func (ce *ConnDataEvent) String() string {
// 	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Addr: %s", ce.Pid, bytes.TrimSpace(ce.Comm[:]), ce.Tid, ce.Fd, ce.Addr)
// 	return s
// }

// func (ce *ConnDataEvent) Clone() IEventStruct {
// 	event := new(ConnDataEvent)
// 	event.eventType = EventTypeModuleData
// 	return event
// }

// func (ce *ConnDataEvent) EventType() EventType {
// 	return ce.eventType
// }

// func (ce *ConnDataEvent) GetUUID() string {
// 	return fmt.Sprintf("%d_%d_%s_%d", ce.Pid, ce.Tid, bytes.TrimSpace(ce.Comm[:]), ce.Fd)
// }

// func (ce *ConnDataEvent) Payload() []byte {
// 	return []byte(ce.Addr)
// }

// func (ce *ConnDataEvent) PayloadLen() int {
// 	return len(ce.Addr)
// }
