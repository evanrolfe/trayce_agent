package internal

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
)

const maxBufferSize = 128

type BufferPacket struct {
	Raw []byte
}

func NewBufferPacket(raw []byte) BufferPacket {
	// Trim the new payload if its null-padded
	if len(raw) > maxBufferSize {
		raw = raw[0:maxBufferSize]
	}
	bp := BufferPacket{Raw: raw}
	bp.Trim()
	return bp
}

func (bp *BufferPacket) AddPayload(payload []byte) {
	bp.Raw = append(bp.Raw, payload...)

	// One the last chunk, it may be null-padded so lets trim it down
	bp.Trim()
}

func (bp *BufferPacket) Debug() {
	// fmt.Println(hex.Dump(bp.raw))
	fmt.Println("Len: ", len(bp.Raw), "TCP Hdr len:", bp.TCPHeaderLen())
	fmt.Println("SAddr: ", bp.SourceAddr())
	fmt.Println("DAddr: ", bp.DestAddr())
	fmt.Println("Protocol: ", bp.Protocol())
	fmt.Println("SPort: ", bp.SourcePort())
	fmt.Println("DPort: ", bp.DestPort())
	fmt.Println("SeqNum: ", bp.SequenceNum())
	fmt.Println("FragOffset: ", bp.FragmentOffset())
	fmt.Println("TotalLen: ", bp.TotalLen())
	fmt.Println("")
	// fmt.Println(string(bp.TCPPayload()))
}

func (bp *BufferPacket) Trim() {
	if len(bp.Raw) > bp.TotalLen() {
		bp.Raw = bp.Raw[0:bp.TotalLen()]
	}
}

func (bp *BufferPacket) IsComplete() bool {
	return (len(bp.Raw) == bp.TotalLen())
}

// -----------------------------------------------------------------------------
// IP Header
// -----------------------------------------------------------------------------
func (bp *BufferPacket) MD5() string {
	return fmt.Sprintf("%x", md5.Sum(bp.Raw[0:20]))
}

func (bp *BufferPacket) SourceAddr() string {
	return fmt.Sprintf("%d.%d.%d.%d", bp.Raw[12], bp.Raw[13], bp.Raw[14], bp.Raw[15])
}

func (bp *BufferPacket) DestAddr() string {
	return fmt.Sprintf("%d.%d.%d.%d", bp.Raw[16], bp.Raw[17], bp.Raw[18], bp.Raw[19])
}

func (bp *BufferPacket) TotalLen() int {
	return int(binary.BigEndian.Uint16(bp.Raw[2:4]))
}

func (bp *BufferPacket) Protocol() int {
	return int(bp.Raw[9])
}

func (bp *BufferPacket) FragmentOffset() int {
	fragmentOffset := int((uint16(bp.Raw[6])<<8 | uint16(bp.Raw[7])) & 0x1FFF)
	return fragmentOffset
}

func (bp *BufferPacket) Payload() []byte {
	return bp.Raw[20:len(bp.Raw)]
}

// -----------------------------------------------------------------------------
// TCP Header
// NOTE: ALL byte positions here include the 20 bytes for the IP header!
// -----------------------------------------------------------------------------
func (bp *BufferPacket) SourcePort() int {
	return int(binary.BigEndian.Uint16(bp.Raw[20:22]))
}

func (bp *BufferPacket) DestPort() int {
	return int(binary.BigEndian.Uint16(bp.Raw[22:24]))
}

func (bp *BufferPacket) SequenceNum() int {
	return int(binary.BigEndian.Uint16(bp.Raw[24:28]))
}

func (bp *BufferPacket) TCPHeaderLen() int {
	return int(bp.Raw[32]>>4) * 4
}

func (bp *BufferPacket) TCPPayload() []byte {
	offset := 20 + bp.TCPHeaderLen()
	return bp.Raw[offset:]
}
