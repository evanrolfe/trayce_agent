package bpf_events

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/evanrolfe/dockerdog/internal/utils"
)

const (
	kSSLRead    = 0
	kSSLWrite   = 1
	kRead       = 2
	kWrite      = 3
	kRecvfrom   = 4
	kSendto     = 5
	TypeEgress  = "egress"
	TypeIngress = "ingress"
)

// DataEvent is sent from ebpf when data is sent or received over a socket, see corresponding: struct data_event_t
type DataEvent struct {
	EventType uint64            `json:"eventType"`
	DataType  uint64            `json:"dataType"`
	Timestamp uint64            `json:"timestamp"`
	Pid       uint32            `json:"pid"`
	Tid       uint32            `json:"tid"`
	Comm      [16]byte          `json:"Comm"`
	Fd        uint32            `json:"fd"`
	Version   int32             `json:"version"`
	Rand      int32             `json:"version"`
	DataLen   int32             `json:"dataLen"`
	Data      [MaxDataSize]byte `json:"data"`
}

func (se *DataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &se.EventType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.DataType); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Timestamp); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Fd); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Version); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Rand); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.DataLen); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Data); err != nil {
		return
	}

	return nil
}

func (se *DataEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d_%d", se.Pid, se.Tid, utils.CToGoString(se.Comm[:]), se.Fd, se.DataType)
}

func (se *DataEvent) Payload() []byte {
	return se.Data[:se.DataLen]
}

func (se *DataEvent) PayloadTrimmed(n int) []byte {
	payload := se.Data[:se.DataLen]

	if len(payload) > n {
		return payload[0:n]
	} else {
		return payload
	}
}

func (se *DataEvent) PayloadLen() int {
	return int(se.DataLen)
}

func (se *DataEvent) Type() string {
	switch AttachType(se.DataType) {
	case kSSLRead:
		return TypeIngress
	case kSSLWrite:
		return TypeEgress
	case kRead:
		return TypeIngress
	case kWrite:
		return TypeEgress
	default:
		return ""
	}
}

func (se *DataEvent) Source() string {
	switch se.DataType {
	case kSSLRead:
		return "SSL_read"
	case kSSLWrite:
		return "SSL_write"
	case kRead:
		return "kprobe/read"
	case kWrite:
		return "kprobe/write"
	case kSendto:
		return "kprobe/sendto"
	case kRecvfrom:
		return "kprobe/recvfrom"
	default:
		return "unkown"
	}
}

func (se *DataEvent) Key() string {
	return fmt.Sprintf("%d-%d", se.Pid, se.Fd)
}

func (se *DataEvent) SSL() bool {
	return se.DataType == kSSLRead || se.DataType == kSSLWrite
}

// IsBlank returns true if the event's payload contains only zero bytes, for some reason we get sent this from ebpf..
func (se *DataEvent) IsBlank() bool {
	for _, b := range se.Payload() {
		if b != 0x00 {
			return false
		}
	}
	return true
}

// func (se *SSLDataEvent) StringHex() string {
// 	//addr := se.module.(*module.MOpenSSLProbe).GetConn(se.Pid, se.Fd)
// 	addr := "[TODO]"
// 	var perfix, connInfo string
// 	switch AttachType(se.DataType) {
// 	case ProbeEntry:
// 		connInfo = fmt.Sprintf("%sRecived %d%s bytes from %s%s%s", COLORGREEN, se.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
// 		perfix = COLORGREEN
// 	case ProbeRet:
// 		connInfo = fmt.Sprintf("%sSend %d%s bytes to %s%s%s", COLORPURPLE, se.DataLen, COLORRESET, COLORYELLOW, addr, COLORRESET)
// 		perfix = fmt.Sprintf("%s\t", COLORPURPLE)
// 	default:
// 		perfix = fmt.Sprintf("UNKNOW_%d", se.DataType)
// 	}

// 	b := dumpByteSlice(se.Data[:se.DataLen], perfix)
// 	b.WriteString(COLORRESET)

// 	v := TlsVersion{Version: se.Version}
// 	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, %s, Version:%s, Payload:\n%s", se.Pid, CToGoString(se.Comm[:]), se.Tid, connInfo, v.String(), b.String())
// 	return s
// }