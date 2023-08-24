package models

// MsgEvent represents data being sent or received over a socket, its different from DataEvent in that each event contains
// a full message of whatever protocol is being used. It also includes the local and remote addresses.
type MsgEvent struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	L4Protocol string `json:"l4_protocol"`
	L7Protocol string `json:"l7_protocol"`
	Type       string `json:"type"`
	Payload    []byte `json:"payload"`
}

func NewMsgEvent(dataEvent *DataEvent, socket *SocketDesc) MsgEvent {
	return MsgEvent{
		Payload:    dataEvent.Data[0:dataEvent.DataLen],
		LocalAddr:  socket.LocalAddr,
		RemoteAddr: socket.RemoteAddr,
		Type:       dataEvent.Type(),
	}
}
