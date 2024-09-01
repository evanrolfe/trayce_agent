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
	EventType   uint64    `json:"eventType"`
	Type        uint64    `json:"type"`
	TimestampNs uint64    `json:"timestampNs"`
	PID         uint32    `json:"pid"`
	TID         uint32    `json:"tid"`
	FD          uint32    `json:"fd"`
	SourceHost  uint32    `json:"source_host"`
	SourcePort  uint16    `json:"source_port"`
	DestHost    uint32    `json:"dest_host"`
	DestPort    uint16    `json:"dest_port"`
	CGroup      [128]byte `json:"cgroup"`
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
	if err = binary.Read(buf, binary.LittleEndian, &ce.SourceHost); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.DestHost); err != nil {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &ce.SourcePort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &ce.DestPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.CGroup); err != nil {
		return
	}

	return nil
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

func (ce *ConnectEvent) CGroupName() string {
	return convertByteArrayToString(ce.CGroup)
}

func (ce *ConnectEvent) SourceAddr() string {
	host := uint32ToIP(ce.SourceHost).String()
	return fmt.Sprintf("%s:%d", host, ce.SourcePort)
}

func (ce *ConnectEvent) DestAddr() string {
	host := uint32ToIP(ce.DestHost).String()
	return fmt.Sprintf("%s:%d", host, ce.DestPort)
}

func uint32ToIP(ipUint32 uint32) net.IP {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ipUint32)

	return net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
}
