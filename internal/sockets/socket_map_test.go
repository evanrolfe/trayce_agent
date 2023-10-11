package sockets_test

import (
	"github.com/evanrolfe/dockerdog/internal/bpf_events"
	"github.com/evanrolfe/dockerdog/internal/sockets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	event1 = `00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
00000010  48 6f 73 74 3a 20 6c 6f  63 61 6c 68 6f 73 74 3a  |Host: localhost:|
00000020  34 31 32 32 0d 0a 55 73  65 72 2d 41 67 65 6e 74  |4122..User-Agent|
00000030  3a 20 70 79 74 68 6f 6e  2d 72 65 71 75 65 73 74  |: python-request|
00000040  73 2f 32 2e 33 31 2e 30  0d 0a 41 63 63 65 70 74  |s/2.31.0..Accept|
00000050  2d 45 6e 63 6f 64 69 6e  67 3a 20 67 7a 69 70 2c  |-Encoding: gzip,|
00000060  20 64 65 66 6c 61 74 65  0d 0a 41 63 63 65 70 74  | deflate..Accept|
00000070  3a 20 2a 2f 2a 0d 0a 43  6f 6e 6e 65 63 74 69 6f  |: */*..Connectio|
00000080  6e 3a 20 6b 65 65 70 2d  61 6c 69 76 65 0d 0a 0d  |n: keep-alive...|
00000090  0a                                                |.|`

	event2 = `00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
00000010  0a 43 6f 6e 74 65 6e 74  2d 54 79 70 65 3a 20 74  |.Content-Type: t|
00000020  65 78 74 2f 70 6c 61 69  6e 0d 0a 44 61 74 65 3a  |ext/plain..Date:|
00000030  20 46 72 69 2c 20 31 35  20 53 65 70 20 32 30 32  | Fri, 15 Sep 202|
00000040  33 20 30 37 3a 31 38 3a  31 38 20 47 4d 54 0d 0a  |3 07:18:18 GMT..|
00000050  43 6f 6e 74 65 6e 74 2d  4c 65 6e 67 74 68 3a 20  |Content-Length: |
00000060  31 33 0d 0a 0d 0a 48 65  6c 6c 6f 20 77 6f 72 6c  |13....Hello worl|
00000070  64 2e 0a                                          |d..|`

	event3 = `00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
00000010  41 63 63 65 70 74 2d 45  6e 63 6f 64 69 6e 67 3a  |Accept-Encoding:|
00000020  20 67 7a 69 70 3b 71 3d  31 2e 30 2c 64 65 66 6c  | gzip;q=1.0,defl|
00000030  61 74 65 3b 71 3d 30 2e  36 2c 69 64 65 6e 74 69  |ate;q=0.6,identi|
00000040  74 79 3b 71 3d 30 2e 33  0d 0a 41 63 63 65 70 74  |ty;q=0.3..Accept|
00000050  3a 20 2a 2f 2a 0d 0a 55  73 65 72 2d 41 67 65 6e  |: */*..User-Agen|
00000060  74 3a 20 52 75 62 79 0d  0a 48 6f 73 74 3a 20 6c  |t: Ruby..Host: l|
00000070  6f 63 61 6c 68 6f 73 74  3a 34 31 32 33 0d 0a 0d  |ocalhost:4123...|
00000080  0a                                                |.|`

	event4 = `00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
00000010  0a 43 6f 6e 74 65 6e 74  2d 54 79 70 65 3a 20 74  |.Content-Type: t|
00000020  65 78 74 2f 70 6c 61 69  6e 0d 0a 44 61 74 65 3a  |ext/plain..Date:|
00000030  20 54 68 75 2c 20 32 31  20 53 65 70 20 32 30 32  | Thu, 21 Sep 202|
00000040  33 20 30 36 3a 35 31 3a  33 35 20 47 4d 54 0d 0a  |3 06:51:35 GMT..|
00000050  43 6f 6e 74 65 6e 74 2d  4c 65 6e 67 74 68 3a 20  |Content-Length: |
00000060  31 33 0d 0a 0d 0a 48 65  6c 6c 6f 20 77 6f 72 6c  |13....Hello worl|
00000070  64 2e 0a                                          |d..|`
)

var _ = Describe("SocketMap", func() {
	event1Payload, _ := hexDumpToBytes(event1)
	event2Payload, _ := hexDumpToBytes(event2)
	// event3Payload, _ := hexDumpToBytes(event3)
	// event4Payload, _ := hexDumpToBytes(event4)

	Context("Receiving a Connect, Data (request) events", Ordered, func() {
		var socketsMap *sockets.SocketMap
		var flows []*sockets.Flow

		BeforeAll(func() {
			socketsMap = sockets.NewSocketMap()
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
				Data:     convertSliceToArray(event1Payload),
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
			Expect(flow.Response).To(BeNil())
		})
	})

	Context("Receiving a Connect, Data (request), Data (response) events", Ordered, func() {
		var socketsMap *sockets.SocketMap
		var flows []*sockets.Flow

		BeforeAll(func() {
			socketsMap = sockets.NewSocketMap()
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
				DataType: 1,
				Data:     convertSliceToArray(event1Payload),
				DataLen:  int32(len(event1Payload)),
			})
			socketsMap.ProcessDataEvent(bpf_events.DataEvent{
				Pid:      123,
				Tid:      123,
				Fd:       5,
				DataType: 0,
				Data:     convertSliceToArray(event2Payload),
				DataLen:  int32(len(event2Payload)),
			})
		})

		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("http"))
				Expect(flow.Pid).To(Equal(123))
				Expect(flow.Fd).To(Equal(5))
			}
		})

		It("the first flow contains an HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).To(Equal(event1Payload))
			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			Expect(flows[1].Response).To(Equal(event2Payload))
		})
	})
})
