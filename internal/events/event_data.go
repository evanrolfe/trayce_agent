package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
)

const (
	KSSLRead    = 0
	KSSLWrite   = 1
	KRead       = 2
	KWrite      = 3
	KRecvfrom   = 4
	KSendto     = 5
	GoTlsRead   = 6
	GoTlsWrite  = 7
	TypeEgress  = "egress"
	TypeIngress = "ingress"
	DIngress    = 0
	DEgress     = 1
)

// DataEvent is sent from ebpf when data is sent or received over a socket, see corresponding: struct data_event_t
type DataEvent struct {
	EventType  uint64            `json:"eventType"`
	DataType   uint64            `json:"dataType"`
	Timestamp  uint64            `json:"timestamp"`
	PID        uint32            `json:"pid"`
	TID        uint32            `json:"tid"`
	CGroup     [128]byte         `json:"cgroup"`
	FD         uint32            `json:"fd"`
	Version    int32             `json:"version"`
	Direction  uint32            `json:"direction"`
	SourceHost uint32            `json:"source_host"`
	DestHost   uint32            `json:"dest_host"`
	SourcePort uint16            `json:"source_port"`
	DestPort   uint16            `json:"dest_port"`
	DataLen    int32             `json:"dataLen"`
	Data       [MaxDataSize]byte `json:"data"`
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
	if err = binary.Read(buf, binary.LittleEndian, &se.CGroup); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.FD); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Version); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.Direction); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.SourceHost); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.DestHost); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.SourcePort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.DestPort); err != nil {
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

func (se *DataEvent) CGroupName() string {
	return convertByteArrayToString(se.CGroup)
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
	case KSSLRead:
		return TypeIngress
	case KSSLWrite:
		return TypeEgress
	case KRead:
		return TypeIngress
	case KWrite:
		return TypeEgress
	case KRecvfrom:
		return TypeIngress
	case KSendto:
		return TypeEgress
	case GoTlsRead:
		return TypeIngress
	case GoTlsWrite:
		return TypeEgress

	default:
		return ""
	}
}

func (se *DataEvent) Source() string {
	switch se.DataType {
	case KSSLRead:
		return "SSL_read"
	case KSSLWrite:
		return "SSL_write"
	case KRead:
		return "kprobe/read"
	case KWrite:
		return "kprobe/write"
	case KRecvfrom:
		return "kprobe/recvfrom"
	case KSendto:
		return "kprobe/sendto"
	case GoTlsRead:
		return "uprobe/go_tls_read"
	case GoTlsWrite:
		return "uprobe/go_tls_write"
	default:
		return "unknown"
	}
}

func (se *DataEvent) Key() string {
	return fmt.Sprintf("%s-%s", se.Address(), se.CGroupName())
}

func intToIP(ipInt uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipInt)
	return ip.String()
}

func (se *DataEvent) Address() string {
	return fmt.Sprintf("%s:%d->%s:%d", intToIP(se.SourceHost), se.SourcePort, intToIP(se.DestHost), se.DestPort)
}

func (se *DataEvent) SourceAddr() string {
	return fmt.Sprintf("%s:%d", intToIP(se.SourceHost), se.SourcePort)
}

func (se *DataEvent) DestAddr() string {
	return fmt.Sprintf("%s:%d", intToIP(se.DestHost), se.DestPort)
}

func (se *DataEvent) SSL() bool {
	sslTypes := []uint64{KSSLRead, KSSLWrite, GoTlsRead, GoTlsWrite}
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

// htons converst host ot network byte order
func htons(x uint16) uint16 {
	return (x&0xff)<<8 | (x&0xff00)>>8
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
