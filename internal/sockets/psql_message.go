package sockets

import (
	"bytes"
	"encoding/binary"
)

// ForkEvent is sent from ebpf when a process is forked to create a child process
type PsqlMessage struct {
	Type    byte
	Length  uint32
	Payload []byte
}

func (de *PsqlMessage) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &de.Type); err != nil {
		return
	}
	if err = binary.Read(buf, binary.BigEndian, &de.Length); err != nil {
		return
	}
	de.Payload = payload[5:]

	return nil
}
