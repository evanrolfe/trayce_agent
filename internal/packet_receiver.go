package internal

import (
	"encoding/hex"
	"fmt"
)

type PacketReceiver struct {
	Packets map[string]*BufferPacket
}

func NewPacketReceiver() PacketReceiver {
	return PacketReceiver{Packets: map[string]*BufferPacket{}}
}

func (pr *PacketReceiver) ReceivePayload(payload []byte) *BufferPacket {
	newPacket := NewBufferPacket(payload)

	_, exists := pr.Packets[newPacket.MD5()]
	if exists {
		fmt.Println("Found existing packet, appending...")
		existingPacket := pr.Packets[newPacket.MD5()]
		existingPacket.ConcatenatePayloads(&newPacket)
	} else {
		fmt.Println("This is a new packet!")
		pr.Packets[newPacket.MD5()] = &newPacket
	}

	fmt.Println("MD5:", newPacket.MD5())
	fmt.Println(hex.Dump(payload))
	fmt.Println("")

	return pr.Packets[newPacket.MD5()]
	// fmt.Println(hex.Dump(packet.Payload()))
}
