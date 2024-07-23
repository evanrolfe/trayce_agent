package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/evanrolfe/trayce_agent/internal/utils"
)

const (
	kSSLRead    = 0
	kSSLWrite   = 1
	kRead       = 2
	kWrite      = 3
	kRecvfrom   = 4
	kSendto     = 5
	goTlsRead   = 6
	goTlsWrite  = 7
	TypeEgress  = "egress"
	TypeIngress = "ingress"
)

// DataEvent is sent from ebpf when data is sent or received over a socket, see corresponding: struct data_event_t
type DataEvent struct {
	EventType uint64            `json:"eventType"`
	DataType  uint64            `json:"dataType"`
	Timestamp uint64            `json:"timestamp"`
	PID       uint32            `json:"pid"`
	TID       uint32            `json:"tid"`
	Comm      [16]byte          `json:"Comm"`
	FD        uint32            `json:"fd"`
	Version   int32             `json:"version"`
	SSLPtr    int64             `json:"sslPtr"`
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
	if err = binary.Read(buf, binary.LittleEndian, &se.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.TID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.FD); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Version); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.SSLPtr); err != nil {
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
	return fmt.Sprintf("%d_%d_%s_%d_%d", se.PID, se.TID, utils.CToGoString(se.Comm[:]), se.FD, se.DataType)
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
	case kRecvfrom:
		return TypeIngress
	case kSendto:
		return TypeEgress
	case goTlsRead:
		return TypeIngress
	case goTlsWrite:
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
	case kRecvfrom:
		return "kprobe/recvfrom"
	case kSendto:
		return "kprobe/sendto"
	case goTlsRead:
		return "uprobe/go_tls_read"
	case goTlsWrite:
		return "uprobe/go_tls_write"
	default:
		return "unknown"
	}
}

func (se *DataEvent) Key() string {
	return fmt.Sprintf("%d-%d", se.PID, se.FD)
}

func (se *DataEvent) SSL() bool {
	sslTypes := []uint64{kSSLRead, kSSLWrite, goTlsRead, goTlsWrite}
	return slices.Contains(sslTypes, se.DataType)
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
