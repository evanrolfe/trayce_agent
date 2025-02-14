package sockets

const (
	TypeMysqlRow   = 0x01
	TypeMysqlQuery = 0x03 // COM_QUERY - Execute an SQL query
	TypeMysqlEOF   = 0xFE
)

// ForkEvent is sent from ebpf when a process is forked to create a child process
type MysqlMessage struct {
	Type        byte
	SequenceNum int
	Payload     []byte
}

func NewMysqlMessage(payload []byte, sequenceNum int) MysqlMessage {
	// fmt.Printf("==========> NewMysqlMessage, type: %d, seq: %d\n", payload[0], sequenceNum)
	// fmt.Println(hex.Dump(payload))
	return MysqlMessage{
		Type:        payload[0],
		SequenceNum: sequenceNum,
		Payload:     payload,
	}
}

// func (my *MysqlMessage) Decode(payload []byte) (err error) {
// 	buf := bytes.NewBuffer(payload)
// 	if err = binary.Read(buf, binary.LittleEndian, &de.Type); err != nil {
// 		return
// 	}
// 	if err = binary.Read(buf, binary.BigEndian, &de.Length); err != nil {
// 		return
// 	}
// 	de.Payload = payload[5:]

// 	return nil
// }
