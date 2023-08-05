package internal

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type DataEvent struct {
	eventType EventType
	DataType  int64             `json:"dataType"`
	Timestamp uint64            `json:"timestamp"`
	Pid       uint32            `json:"pid"`
	Tid       uint32            `json:"tid"`
	Data      [MaxDataSize]byte `json:"data"`
	DataLen   int32             `json:"dataLen"`
	Comm      [16]byte          `json:"Comm"`
	Fd        uint32            `json:"fd"`
	Version   int32             `json:"version"`
}

func (se *DataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
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
	if err = binary.Read(buf, binary.LittleEndian, &se.Data); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &se.DataLen); err != nil {
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

	return nil
}

func (se *DataEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d_%d", se.Pid, se.Tid, CToGoString(se.Comm[:]), se.Fd, se.DataType)
}

func (se *DataEvent) Payload() []byte {
	return se.Data[:se.DataLen]
}

func (se *DataEvent) PayloadLen() int {
	return int(se.DataLen)
}

func (se *DataEvent) Type() string {
	switch AttachType(se.DataType) {
	case ProbeEntry:
		return "ProbeEntry"
	case ProbeRet:
		return "ProbeReturn"
	default:
		return "unknown"
	}
}

func (se *DataEvent) Key() string {
	return fmt.Sprintf("%d-%d", se.Pid, se.Tid)
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
