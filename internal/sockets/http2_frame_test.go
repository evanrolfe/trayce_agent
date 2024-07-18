package sockets_test

import (
	"github.com/evanrolfe/trayce_agent/internal/sockets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	payload1 = `00000000  00 00 0d 00 01 00 00 00  01 48 65 6c 6c 6f 20 77  |.........Hello w|`

	payload2 = `00000000  00 00 0d 00 01 00 00 00  01 48 65 6c 6c 6f 20 77  |.........Hello w|
	00000010  6f 72 6c 64 2e 0a                                 |orld..|`

	payload3 = `00000000  00 00 00 04 01 00 00 00  00 00 00 04 08 00 00 00  |................|
	00000010  00 00 00 0f 00 01 00 00  26 01 04 00 00 00 01 88  |........&.......|
	00000020  5f 87 49 7c a5 8a e8 19  aa 5c 02 31 33 61 96 df  |_.I|.....\.13a..|
	00000030  69 7e 94 0b 8a 65 b6 85  04 01 34 a0 1e b8 db b7  |i~...e....4.....|
	00000040  04 25 31 68 df                                    |.%1h.|`
)

var _ = Describe("HTTP2Frame", func() {
	Describe("ParseBytesToFrames()", func() {
		When("the bytes contain an incomplete frame", func() {
			It("returns no frames and the remaining bytes", func() {
				payload, err := hexDumpToBytes(payload1)
				Expect(err).To(BeNil())

				frames, remainder := sockets.ParseBytesToFrames(payload)
				Expect(len(frames)).To(Equal(0))
				Expect(remainder).To(Equal(payload))
			})
		})

		When("the bytes contain a single complete frames", func() {
			It("returns a single frame", func() {
				payload, err := hexDumpToBytes(payload2)
				Expect(err).To(BeNil())

				frames, remainder := sockets.ParseBytesToFrames(payload)
				Expect(len(frames)).To(Equal(1))
				Expect(string(frames[0].Payload())).To(Equal("Hello world.\n"))
				Expect(remainder).To(BeEmpty())
			})
		})

		When("the bytes contain multiple frames", func() {
			It("returns multiple frames", func() {
				payload, err := hexDumpToBytes(payload3)
				Expect(err).To(BeNil())

				frames, _ := sockets.ParseBytesToFrames(payload)
				Expect(len(frames)).To(Equal(3))

				Expect(len(frames[0].Payload())).To(Equal(0))
				Expect(len(frames[1].Payload())).To(Equal(4))
				Expect(len(frames[2].Payload())).To(Equal(38))
			})
		})
	})

	Describe("Complete()", func() {
		It("returns incomplete for [00 00 00]", func() {
			frame := sockets.NewHttp2Frame([]byte{0, 0, 0})
			Expect(frame.Complete()).To(BeFalse())
		})

		It("returns incomplete for [00 00 03]", func() {
			frame := sockets.NewHttp2Frame([]byte{0, 0, 3})
			Expect(frame.Complete()).To(BeFalse())
		})

		It("returns incomplete for [00 00 00 04 01]", func() {
			frame := sockets.NewHttp2Frame([]byte{0, 0, 0, 4, 1})
			Expect(frame.Complete()).To(BeFalse())
		})

		It("returns complete for [00 00 00 04 01 00 00 00 00]", func() {
			frame := sockets.NewHttp2Frame([]byte{0, 0, 0, 4, 1, 0, 0, 0, 0})
			Expect(frame.Complete()).To(BeTrue())
		})

		It("returns complete for [00 00 03 04 01 00 00 00 00 01 02 03]", func() {
			frame := sockets.NewHttp2Frame([]byte{0, 0, 3, 4, 1, 0, 0, 0, 0, 1, 2, 3})
			Expect(frame.Complete()).To(BeTrue())
		})
	})
})
