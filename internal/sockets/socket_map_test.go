package sockets_test

import (
	"github.com/evanrolfe/dockerdog/internal/bpf_events"
	"github.com/evanrolfe/dockerdog/internal/sockets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const event1 = `00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
00000010  48 6f 73 74 3a 20 6c 6f  63 61 6c 68 6f 73 74 3a  |Host: localhost:|
00000020  34 31 32 32 0d 0a 55 73  65 72 2d 41 67 65 6e 74  |4122..User-Agent|
00000030  3a 20 70 79 74 68 6f 6e  2d 72 65 71 75 65 73 74  |: python-request|
00000040  73 2f 32 2e 33 31 2e 30  0d 0a 41 63 63 65 70 74  |s/2.31.0..Accept|
00000050  2d 45 6e 63 6f 64 69 6e  67 3a 20 67 7a 69 70 2c  |-Encoding: gzip,|
00000060  20 64 65 66 6c 61 74 65  0d 0a 41 63 63 65 70 74  | deflate..Accept|
00000070  3a 20 2a 2f 2a 0d 0a 43  6f 6e 6e 65 63 74 69 6f  |: */*..Connectio|
00000080  6e 3a 20 6b 65 65 70 2d  61 6c 69 76 65 0d 0a 0d  |n: keep-alive...|
00000090  0a                                                |.|`

var _ = Describe("SocketMap", func() {
	Context("Receiving a Connect, Data events", Ordered, func() {
		var socketsMap *sockets.SocketMap
		var flows []*sockets.Flow
		event1Payload, _ := hexDumpToBytes(event1)
		socketsMap = sockets.NewSocketMap()

		BeforeAll(func() {
			var data [4096]byte
			copy(data[:], event1Payload)

			socketsMap.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})
			socketsMap.ProcessConnectEvent(bpf_events.ConnectEvent{
				Pid:  123,
				Tid:  123,
				Fd:   5,
				Ip:   2130706433,
				Port: 80,
			})
			socketsMap.ProcessDataEvent(bpf_events.DataEvent{
				Pid:      123,
				Tid:      123,
				Fd:       5,
				DataType: 1, // TODO: Use the constant from bpf_events kSSLWrite
				Data:     data,
				DataLen:  int32(len(event1Payload)),
			})
		})

		It("returns a flow", func() {
			Expect(flows).To(HaveLen(1))

			flow := flows[0]
			Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http"))
			Expect(flow.Pid).To(Equal(123))
			Expect(flow.Fd).To(Equal(5))
		})

		It("the flow contains the HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).To(Equal(event1Payload))
		})
	})
})
