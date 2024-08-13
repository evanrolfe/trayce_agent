package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	kConnect = 0
	kAccept  = 1
)

// ConnectEvent is sent from ebpf when a socket is connected, see corresponding: struct connect_event_t
type ConnectEvent struct {
	EventType   uint64 `json:"eventType"`
	Type        uint64 `json:"type"`
	TimestampNs uint64 `json:"timestampNs"`
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	FD          uint32 `json:"fd"`
	IP          uint32 `json:"ip"`
	Port        uint16 `json:"port"`
	Local       bool   `json:"local"`
	SSL         bool   `json:"ssl"`
	Protocol    uint32 `json:"protocol"`
	LocalIP     uint32 `json:"localIp"`
}

func (ce *ConnectEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ce.EventType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Type); err != nil {
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
	if err = binary.Read(buf, binary.BigEndian, &ce.IP); err != nil {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &ce.Port); err != nil {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &ce.Local); err != nil {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &ce.SSL); err != nil {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &ce.Protocol); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.LocalIP); err != nil {
		return
	}

	return nil
}

func (ce *ConnectEvent) IPAddr() string {
	ipBytes := make([]byte, 4)
	ipBytes[0] = byte(ce.IP >> 24)
	ipBytes[1] = byte(ce.IP >> 16)
	ipBytes[2] = byte(ce.IP >> 8)
	ipBytes[3] = byte(ce.IP)
	ipAddr := net.IP(ipBytes)

	return ipAddr.String()
}

func (ce *ConnectEvent) LocalIPAddr() string {
	ipBytes := make([]byte, 4)
	ipBytes[0] = byte(ce.LocalIP >> 24)
	ipBytes[1] = byte(ce.LocalIP >> 16)
	ipBytes[2] = byte(ce.LocalIP >> 8)
	ipBytes[3] = byte(ce.LocalIP)
	ipAddr := net.IP(ipBytes)

	return ipAddr.String()
}

func (ce *ConnectEvent) Key() string {
	return fmt.Sprintf("%d-%d", ce.PID, ce.FD)
}

func (ce *ConnectEvent) TypeStr() string {
	switch ce.Type {
	case kConnect:
		return "connect"
	case kAccept:
		return "accept"
	default:
		return ""
	}
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
