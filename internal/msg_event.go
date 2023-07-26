package internal

type MsgEvent struct {
	Ip      string `json:"ip"`
	Port    int    `json:"port"`
	Payload []byte `json:"payload"`
}
