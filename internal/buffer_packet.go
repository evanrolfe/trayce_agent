package internal

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const maxBufferSize = 128

type BufferPacket struct {
	raw []byte
}

func NewBufferPacket(raw []byte) BufferPacket {
	// Trim the new payload if its null-padded
	if len(raw) > maxBufferSize {
		raw = raw[0:maxBufferSize]
	}
	bp := BufferPacket{raw: raw}
	bp.Trim()
	return bp
}

func (bp *BufferPacket) ConcatenatePayloads(newPacket *BufferPacket) {
	bp.raw = append(bp.raw, newPacket.Payload()...)

	// One the last chunk, it may be null-padded so lets trim it down
	bp.Trim()
}

func (bp *BufferPacket) Debug() {
	fmt.Println(hex.Dump(bp.raw))
	fmt.Println("Len: ", len(bp.raw), "TCP Hdr len:", bp.TCPHeaderLen())
	fmt.Println("SAddr: ", bp.SourceAddr())
	fmt.Println("DAddr: ", bp.DestAddr())
	fmt.Println("Protocol: ", bp.Protocol())
	fmt.Println("SPort: ", bp.SourcePort())
	fmt.Println("DPort: ", bp.DestPort())
	fmt.Println(string(bp.TCPPayload()))
}

func (bp *BufferPacket) Trim() {
	if len(bp.raw) > bp.TotalLen() {
		bp.raw = bp.raw[0:bp.TotalLen()]
	}
}

func (bp *BufferPacket) IsComplete() bool {
	return (len(bp.raw) == bp.TotalLen())
}

// -----------------------------------------------------------------------------
// IP Header
// -----------------------------------------------------------------------------
func (bp *BufferPacket) MD5() string {
	return fmt.Sprintf("%x", md5.Sum(bp.raw[0:20]))
}

func (bp *BufferPacket) SourceAddr() string {
	return fmt.Sprintf("%d.%d.%d.%d", bp.raw[12], bp.raw[13], bp.raw[14], bp.raw[15])
}

func (bp *BufferPacket) DestAddr() string {
	return fmt.Sprintf("%d.%d.%d.%d", bp.raw[16], bp.raw[17], bp.raw[18], bp.raw[19])
}

func (bp *BufferPacket) TotalLen() int {
	return int(binary.BigEndian.Uint16(bp.raw[2:4]))
}

func (bp *BufferPacket) Protocol() int {
	return int(bp.raw[9])
}

func (bp *BufferPacket) Payload() []byte {
	return bp.raw[20:len(bp.raw)]
}

// -----------------------------------------------------------------------------
// TCP Header
// NOTE: ALL byte positions here include the 20 bytes for the IP header!
// -----------------------------------------------------------------------------
func (bp *BufferPacket) SourcePort() int {
	return int(binary.BigEndian.Uint16(bp.raw[20:22]))
}

func (bp *BufferPacket) DestPort() int {
	return int(binary.BigEndian.Uint16(bp.raw[22:24]))
}

func (bp *BufferPacket) TCPHeaderLen() int {
	return int(bp.raw[32]>>4) * 4
}

func (bp *BufferPacket) TCPPayload() []byte {
	offset := 20 + bp.TCPHeaderLen()
	return bp.raw[offset:]
}
