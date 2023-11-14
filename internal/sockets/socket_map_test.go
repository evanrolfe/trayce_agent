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

	event5 = `00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
00000010  48 6f 73 74 3a 20 77 77  77 2e 70 6e 74 65 73 74  |Host: www.pntest|
00000020  2e 69 6f 0d 0a 55 73 65  72 2d 41 67 65 6e 74 3a  |.io..User-Agent:|
00000030  20 47 6f 2d 68 74 74 70  2d 63 6c 69 65 6e 74 2f  | Go-http-client/|
00000040  31 2e 31 0d 0a 41 63 63  65 70 74 2d 45 6e 63 6f  |1.1..Accept-Enco|
00000050  64 69 6e 67 3a 20 67 7a  69 70 0d 0a 0d 0a        |ding: gzip....|`

	event6 = `00000000  48 54 54 50 2f 31 2e 31  20 33 30 31 20 4d 6f 76  |HTTP/1.1 301 Mov|
00000010  65 64 20 50 65 72 6d 61  6e 65 6e 74 6c 79 0d 0a  |ed Permanently..|
00000020  44 61 74 65 3a 20 53 61  74 2c 20 30 34 20 4e 6f  |Date: Sat, 04 No|
00000030  76 20 32 30 32 33 20 32  30 3a 30 35 3a 31 34 20  |v 2023 20:05:14 |
00000040  47 4d 54 0d 0a 43 6f 6e  74 65 6e 74 2d 54 79 70  |GMT..Content-Typ|
00000050  65 3a 20 74 65 78 74 2f  68 74 6d 6c 0d 0a 54 72  |e: text/html..Tr|
00000060  61 6e 73 66 65 72 2d 45  6e 63 6f 64 69 6e 67 3a  |ansfer-Encoding:|
00000070  20 63 68 75 6e 6b 65 64  0d 0a 43 6f 6e 6e 65 63  | chunked..Connec|
00000080  74 69 6f 6e 3a 20 6b 65  65 70 2d 61 6c 69 76 65  |tion: keep-alive|
00000090  0d 0a 4c 6f 63 61 74 69  6f 6e 3a 20 68 74 74 70  |..Location: http|
000000a0  3a 2f 2f 70 6e 74 65 73  74 2e 69 6f 2f 0d 0a 58  |://pntest.io/..X|
000000b0  2d 47 69 74 68 75 62 2d  52 65 71 75 65 73 74 2d  |-Github-Request-|
000000c0  49 64 3a 20 41 31 44 32  3a 31 32 43 30 36 3a 31  |Id: A1D2:12C06:1|
000000d0  38 34 45 38 37 44 3a 31  38 42 46 35 33 30 3a 36  |84E87D:18BF530:6|
000000e0  35 34 36 41 31 33 41 0d  0a 41 63 63 65 70 74 2d  |546A13A..Accept-|
000000f0  52 61 6e 67 65 73 3a 20  62 79 74 65 73 0d 0a 56  |Ranges: bytes..V|
00000100  69 61 3a 20 31 2e 31 20  76 61 72 6e 69 73 68 0d  |ia: 1.1 varnish.|
00000110  0a 41 67 65 3a 20 37 30  34 0d 0a 58 2d 53 65 72  |.Age: 704..X-Ser|
00000120  76 65 64 2d 42 79 3a 20  63 61 63 68 65 2d 6d 61  |ved-By: cache-ma|
00000130  6e 34 31 34 36 2d 4d 41  4e 0d 0a 58 2d 43 61 63  |n4146-MAN..X-Cac|
00000140  68 65 3a 20 48 49 54 0d  0a 58 2d 43 61 63 68 65  |he: HIT..X-Cache|
00000150  2d 48 69 74 73 3a 20 31  0d 0a 58 2d 54 69 6d 65  |-Hits: 1..X-Time|
00000160  72 3a 20 53 31 36 39 39  31 32 38 33 31 35 2e 38  |r: S1699128315.8|
00000170  39 31 32 39 38 2c 56 53  30 2c 56 45 32 0d 0a 56  |91298,VS0,VE2..V|
00000180  61 72 79 3a 20 41 63 63  65 70 74 2d 45 6e 63 6f  |ary: Accept-Enco|
00000190  64 69 6e 67 0d 0a 58 2d  46 61 73 74 6c 79 2d 52  |ding..X-Fastly-R|
000001a0  65 71 75 65 73 74 2d 49  64 3a 20 30 62 35 61 39  |equest-Id: 0b5a9|
000001b0  63 33 65 33 62 32 65 37  37 31 64 30 65 65 66 62  |c3e3b2e771d0eefb|
000001c0  33 64 37 30 63 34 35 61  63 64 33 30 37 63 35 63  |3d70c45acd307c5c|
000001d0  30 31 37 0d 0a 43 66 2d  43 61 63 68 65 2d 53 74  |017..Cf-Cache-St|
000001e0  61 74 75 73 3a 20 44 59  4e 41 4d 49 43 0d 0a 52  |atus: DYNAMIC..R|
000001f0  65 70 6f 72 74 2d 54 6f  3a 20 7b 22 65 6e 64 70  |eport-To: {"endp|
00000200  6f 69 6e 74 73 22 3a 5b  7b 22 75 72 6c 22 3a 22  |oints":[{"url":"|
00000210  68 74 74 70 73 3a 5c 2f  5c 2f 61 2e 6e 65 6c 2e  |https:\/\/a.nel.|
00000220  63 6c 6f 75 64 66 6c 61  72 65 2e 63 6f 6d 5c 2f  |cloudflare.com\/|
00000230  72 65 70 6f 72 74 5c 2f  76 33 3f 73 3d 53 43 73  |report\/v3?s=SCs|
00000240  74 6d 4a 68 6c 57 45 65  41 4c 41 70 62 4c 64 6f  |tmJhlWEeALApbLdo|
00000250  61 75 55 52 58 42 51 33  62 70 70 73 6b 57 47 59  |auURXBQ3bppskWGY|
00000260  55 39 51 71 76 68 48 33  73 33 44 37 69 79 4e 65  |U9QqvhH3s3D7iyNe|
00000270  69 25 32 46 6d 37 30 76  66 31 53 30 39 35 25 32  |i%2Fm70vf1S095%2|
00000280  46 77 51 59 64 4c 30 4f  54 72 62 74 32 57 69 46  |FwQYdL0OTrbt2WiF|
00000290  6b 30 6b 70 44 71 33 4a  63 25 32 42 6c 4e 47 4f  |k0kpDq3Jc%2BlNGO|
000002a0  4c 4b 47 25 32 46 6c 4c  4f 5a 69 44 56 6c 54 72  |LKG%2FlLOZiDVlTr|
000002b0  35 37 76 5a 6c 64 30 36  5a 53 57 34 69 58 45 4a  |57vZld06ZSW4iXEJ|
000002c0  62 6c 53 6c 44 22 7d 5d  2c 22 67 72 6f 75 70 22  |blSlD"}],"group"|
000002d0  3a 22 63 66 2d 6e 65 6c  22 2c 22 6d 61 78 5f 61  |:"cf-nel","max_a|
000002e0  67 65 22 3a 36 30 34 38  30 30 7d 0d 0a 4e 65 6c  |ge":604800}..Nel|
000002f0  3a 20 7b 22 73 75 63 63  65 73 73 5f 66 72 61 63  |: {"success_frac|
00000300  74 69 6f 6e 22 3a 30 2c  22 72 65 70 6f 72 74 5f  |tion":0,"report_|
00000310  74 6f 22 3a 22 63 66 2d  6e 65 6c 22 2c 22 6d 61  |to":"cf-nel","ma|
00000320  78 5f 61 67 65 22 3a 36  30 34 38 30 30 7d 0d 0a  |x_age":604800}..|
00000330  53 65 72 76 65 72 3a 20  63 6c 6f 75 64 66 6c 61  |Server: cloudfla|
00000340  72 65 0d 0a 43 66 2d 52  61 79 3a 20 38 32 30 66  |re..Cf-Ray: 820f|
00000350  37 38 37 66 66 39 36 61  30 37 34 32 2d 4d 41 4e  |787ff96a0742-MAN|
00000360  0d 0a 41 6c 74 2d 53 76  63 3a 20 68 33 3d 22 3a  |..Alt-Svc: h3=":|
00000370  34 34 33 22 3b 20 6d 61  3d 38 36 34 30 30 0d 0a  |443"; ma=86400..|
00000380  0d 0a 61 32 0d 0a 3c 68  74 6d 6c 3e 0d 0a 3c 68  |..a2..<html>..<h|
00000390  65 61 64 3e 3c 74 69 74  6c 65 3e 33 30 31 20 4d  |ead><title>301 M|
000003a0  6f 76 65 64 20 50 65 72  6d 61 6e 65 6e 74 6c 79  |oved Permanently|
000003b0  3c 2f 74 69 74 6c 65 3e  3c 2f 68 65 61 64 3e 0d  |</title></head>.|
000003c0  0a 3c 62 6f 64 79 3e 0d  0a 3c 63 65 6e 74 65 72  |.<body>..<center|
000003d0  3e 3c 68 31 3e 33 30 31  20 4d 6f 76 65 64 20 50  |><h1>301 Moved P|
000003e0  65 72 6d 61 6e 65 6e 74  6c 79 3c 2f 68 31 3e 3c  |ermanently</h1><|
000003f0  2f 63 65 6e 74 65 72 3e  0d 0a 3c 68 72 3e 3c 63  |/center>..<hr><c|
00000400  65 6e 74 65 72 3e 6e 67  69 6e 78 3c 2f 63 65 6e  |enter>nginx</cen|
00000410  74 65 72 3e 0d 0a 3c 2f  62 6f 64 79 3e 0d 0a 3c  |ter>..</body>..<|
00000420  2f 68 74 6d 6c 3e 0d 0a  0d 0a 00 00 00 00 00 00  |/html>..........|
00000430  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000440  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000450  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|`

	event7 = `00000000  47 45 54 20 2f 63 68 75  6e 6b 65 64 20 48 54 54  |GET /chunked HTT|
00000010  50 2f 31 2e 31 0d 0a 48  6f 73 74 3a 20 6c 6f 63  |P/1.1..Host: loc|
00000020  61 6c 68 6f 73 74 3a 34  31 32 33 0d 0a 55 73 65  |alhost:4123..Use|
00000030  72 2d 41 67 65 6e 74 3a  20 47 6f 2d 68 74 74 70  |r-Agent: Go-http|
00000040  2d 63 6c 69 65 6e 74 2f  31 2e 31 0d 0a 41 63 63  |-client/1.1..Acc|
00000050  65 70 74 2d 45 6e 63 6f  64 69 6e 67 3a 20 69 64  |ept-Encoding: id|
00000060  65 6e 74 69 74 79 0d 0a  0d 0a                    |entity....|`

	event8 = `00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  |HTTP/1.1 200 OK.|
00000010  0a 58 2d 43 6f 6e 74 65  6e 74 2d 54 79 70 65 2d  |.X-Content-Type-|
00000020  4f 70 74 69 6f 6e 73 3a  20 6e 6f 73 6e 69 66 66  |Options: nosniff|
00000030  0d 0a 44 61 74 65 3a 20  4d 6f 6e 2c 20 31 33 20  |..Date: Mon, 13 |
00000040  4e 6f 76 20 32 30 32 33  20 30 37 3a 35 36 3a 31  |Nov 2023 07:56:1|
00000050  38 20 47 4d 54 0d 0a 54  72 61 6e 73 66 65 72 2d  |8 GMT..Transfer-|
00000060  45 6e 63 6f 64 69 6e 67  3a 20 63 68 75 6e 6b 65  |Encoding: chunke|
00000070  64 0d 0a 0d 0a 39 0d 0a  43 68 75 6e 6b 20 23 31  |d....9..Chunk #1|
00000080  0a 0d 0a                                          |...|`

	event9 = `00000000  39 0d 0a 43 68 75 6e 6b  20 23 32 0a 0d 0a        |9..Chunk #2...|`

	event10 = `00000000  39 0d 0a 43 68 75 6e 6b  20 23 33 0a 0d 0a        |9..Chunk #3...|`

	event11 = `00000000  39 0d 0a 43 68 75 6e 6b  20 23 34 0a 0d 0a        |9..Chunk #4...|`

	event12 = `00000000  39 0d 0a 43 68 75 6e 6b  20 23 35 0a 0d 0a        |9..Chunk #5...|`

	event13 = `00000000  30 0d 0a 0d 0a                                    |0....|`
)

var _ = Describe("SocketMap", func() {
	event1Payload, _ := hexDumpToBytes(event1)
	event2Payload, _ := hexDumpToBytes(event2)
	// event3Payload, _ := hexDumpToBytes(event3)
	// event4Payload, _ := hexDumpToBytes(event4)
	event5Payload, _ := hexDumpToBytes(event5)
	event6Payload, _ := hexDumpToBytes(event6)

	event7Payload, _ := hexDumpToBytes(event7)
	event8Payload, _ := hexDumpToBytes(event8)
	event9Payload, _ := hexDumpToBytes(event9)
	event10Payload, _ := hexDumpToBytes(event10)
	event11Payload, _ := hexDumpToBytes(event11)
	event12Payload, _ := hexDumpToBytes(event12)
	event13Payload, _ := hexDumpToBytes(event13)

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

	Context("Receiving a Connect, Data (request), Data (response) events (scenario 2)", Ordered, func() {
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
				Data:     convertSliceToArray(event5Payload),
				DataLen:  int32(len(event5Payload)),
			})
			socketsMap.ProcessDataEvent(bpf_events.DataEvent{
				Pid:      123,
				Tid:      123,
				Fd:       5,
				DataType: 0,
				Data:     convertSliceToArray(event6Payload),
				DataLen:  int32(len(event6Payload)),
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
			Expect(flow.Request).To(Equal(event5Payload))
			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			Expect(flows[1].Response).To(Equal(event6Payload[:1066])) // without the trailing zeroes
		})
	})

	Context("Receiving a Connect, Data (request), Data (response) events (chunked) from Go", Ordered, func() {
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
				DataType: 7, // goTlsWrite
				Data:     convertSliceToArray(event7Payload),
				DataLen:  int32(len(event7Payload)),
			})

			dataEvents := [][4096]byte{
				convertSliceToArray(event8Payload),
				convertSliceToArray(event9Payload),
				convertSliceToArray(event10Payload),
				convertSliceToArray(event11Payload),
				convertSliceToArray(event12Payload),
				convertSliceToArray(event13Payload),
			}

			for _, event := range dataEvents {
				socketsMap.ProcessDataEvent(bpf_events.DataEvent{
					Pid:      123,
					Tid:      123,
					Fd:       5,
					DataType: 6, // goTlsRead
					Data:     event,
					DataLen:  int32(len(event)),
				})
			}
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
			Expect(flow.Request).To(Equal(event7Payload))
			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			// Expect(flows[1].Response).To(Equal(event7Payload)) // without the trailing zeroes

			// fmt.Println(string(flows[1].Response))
		})
	})
})
