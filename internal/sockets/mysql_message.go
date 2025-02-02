package sockets

const (
	TypeMysqlRow   = 0x01
	TypeMysqlQuery = 0x03 // COM_QUERY - Execute an SQL query
	TypeMysqlEOF   = 0xFE
)

// ForkEvent is sent from ebpf when a process is forked to create a child process
type MysqlMessage struct {
	Type    byte
	Payload []byte
}

func NewMysqlMessage(payload []byte) MysqlMessage {
	return MysqlMessage{
		Type:    payload[0],
		Payload: payload[1:],
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
