package models

type MsgEvent struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	L4Protocol string `json:"l4_protocol"`
	L7Protocol string `json:"l7_protocol"`
	Payload    []byte `json:"payload"`
}

func NewMsgEvent(dataEvent *DataEvent, socket *SocketDesc) MsgEvent {
	return MsgEvent{
		Payload:    dataEvent.Data[0:dataEvent.DataLen],
		LocalAddr:  socket.LocalAddr,
		RemoteAddr: socket.RemoteAddr,
	}
}
