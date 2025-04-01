package sockets

import (
	"bytes"
	"encoding/binary"
)

const (
	TypeQuery           = 0x51 // Q - a standard postgres query
	TypeParse           = 0x50 // P - a prepared postgres query
	TypeBind            = 0x42 // B - binding
	TypeParseComplete   = 0x31 // 1 - server has successfully parsed a query
	TypeParamDesc       = 0x74 // t
	TypeRowDesc         = 0x54 // T - row description contains the columns being sent back
	TypeDataRow         = 0x44 // D - a row of data
	TypeCommandComplete = 0x43 // C - the command is complete and all data has been sent
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

func (de *PsqlMessage) Complete() bool {
	return int(de.Length) == len(de.Payload)+4 // Add 4 bytes onto the count because the length includes the length itself
}
