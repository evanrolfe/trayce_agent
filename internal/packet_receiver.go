package internal

type PacketReceiver struct {
	Packets []*BufferPacket
}

func NewPacketReceiver() PacketReceiver {
	return PacketReceiver{Packets: []*BufferPacket{}}
}

func (pr *PacketReceiver) ReceivePayload(payload []byte) *BufferPacket {
	if len(pr.Packets) == 0 {
		newPacket := NewBufferPacket(payload)
		pr.Packets = append(pr.Packets, &newPacket)
		return &newPacket
	}

	lastPacket := pr.Packets[len(pr.Packets)-1]
	if lastPacket.IsComplete() {
		// fmt.Println("last packet complete, creating a new one")
		// fmt.Println(hex.Dump(payload))
		newPacket := NewBufferPacket(payload)
		pr.Packets = append(pr.Packets, &newPacket)
		return &newPacket
	}

	// fmt.Println("appending payload to last packet")
	lastPacket.AddPayload(payload)

	// fmt.Printf("	TotalLen: %d, raw len: %d\n", lastPacket.TotalLen(), len(lastPacket.Raw))
	return lastPacket
}
