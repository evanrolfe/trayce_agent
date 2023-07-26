package parse

import "fmt"

type Message struct {
	raw      []byte
	Complete bool
}

func (msg *Message) AppendBytes(raw []byte) {
	msg.raw = append(msg.raw, raw...)
}

func (msg *Message) SetComplete() {
	msg.Complete = true
}

type MessageCollector struct {
	Messages []*Message
}

func NewMessageCollector() *MessageCollector {
	return &MessageCollector{Messages: []*Message{}}
}

func (mc *MessageCollector) CollectBytes(raw []byte) {
	message := mc.LastIncompleteMessage()
	message.AppendBytes(raw)
}

func (mc *MessageCollector) CompleteLastMessage() {
	if len(mc.Messages) == 0 {
		fmt.Println("NO LAST MESSAGE!")
		return
	}

	lastMessage := mc.Messages[len(mc.Messages)-1]
	lastMessage.SetComplete()

	fmt.Println(string(lastMessage.raw))
}

func (mc *MessageCollector) LastIncompleteMessage() *Message {
	if len(mc.Messages) == 0 {
		newMessage := &Message{raw: []byte{}, Complete: false}
		mc.Messages = append(mc.Messages, newMessage)
		return newMessage
	}

	lastMessage := mc.Messages[len(mc.Messages)-1]
	if !lastMessage.Complete {
		return lastMessage
	}

	newMessage := &Message{raw: []byte{}, Complete: false}
	mc.Messages = append(mc.Messages, newMessage)
	return newMessage
}
