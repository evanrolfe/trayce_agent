package internal

type MsgEvent struct {
	Ip         string `json:"ip"`
	Port       int    `json:"port"`
	L4Protocol string `json:"l4_protocol"`
	L7Protocol string `json:"l7_protocol"`
	Payload    []byte `json:"payload"`
}

func NewMsgEvent(dataEvent *DataEvent, connEvent *SocketAddrEvent) MsgEvent {
	return MsgEvent{
		Payload: dataEvent.Data[0:dataEvent.DataLen],
		Ip:      connEvent.IPAddr(),
		Port:    int(connEvent.Port),
	}
}
