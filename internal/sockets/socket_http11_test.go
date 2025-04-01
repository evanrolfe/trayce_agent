package sockets_test

import (
	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/evanrolfe/trayce_agent/internal/sockets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SocketHTTP1.1", func() {
	event1Payload, _ := hexDumpToBytes(event1)
	event2Payload, _ := hexDumpToBytes(event2)

	event5Payload, _ := hexDumpToBytes(event5)
	event6Payload, _ := hexDumpToBytes(event6)

	event7Payload, _ := hexDumpToBytes(event7)
	event8Payload, _ := hexDumpToBytes(event8)
	event9Payload, _ := hexDumpToBytes(event9)
	event10Payload, _ := hexDumpToBytes(event10)
	event11Payload, _ := hexDumpToBytes(event11)
	event12Payload, _ := hexDumpToBytes(event12)
	event13Payload, _ := hexDumpToBytes(event13)

	gzip1Payload, _ := hexDumpToBytes(gzipEvent1)
	gzip2Payload, _ := hexDumpToBytes(gzipEvent2)

	post1Payload, _ := hexDumpToBytes(eventPost1)

	Context("Receiving Data (request) events", Ordered, func() {
		var flows []*sockets.Flow
		payloads := [][]byte{
			event1Payload,
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 1, // TODO: Use the constant from bpf_events kSSLWrite
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a flow", func() {
			Expect(flows).To(HaveLen(1))

			flow := flows[0]
			Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
			Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))
		})

		It("the flow contains the HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("GET"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("1.1"))
			Expect(req.Host).To(Equal("localhost:4122"))

			Expect(req.Headers["Accept"]).To(Equal([]string{"*/*"}))
			Expect(req.Headers["Accept-Encoding"]).To(Equal([]string{"gzip, deflate"}))
			Expect(req.Headers["Connection"]).To(Equal([]string{"keep-alive"}))
			Expect(req.Headers["User-Agent"]).To(Equal([]string{"python-requests/2.31.0"}))
		})
	})

	Context("Receiving Data (request), Getsockname, events", Ordered, func() {
		var flows []*sockets.Flow
		payloads := [][]byte{
			event1Payload,
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 1, // TODO: Use the constant from bpf_events kSSLWrite
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a flow", func() {
			Expect(flows).To(HaveLen(1))

			flow := flows[0]
			Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
			Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))
		})

		It("the flow contains the HTTP request", func() {
			flow := flows[0]
			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("GET"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("1.1"))
			Expect(req.Host).To(Equal("localhost:4122"))

			Expect(flow.Response).To(BeNil())
		})
	})

	// In HTTPS we get both the encrypted & decrypted versions of the same event sent, so we have to ensure only the
	// encrypted one is processed
	Context("Receiving TLS Data (request), Non-TLS Data, TLS Data (response) events", Ordered, func() {
		var flows []*sockets.Flow
		randomPayload := []byte{0x00, 0x00, 0x26, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x88, 0x5f, 0x87, 0x49, 0x7c, 0xa5, 0x8a, 0xe8, 0x19, 0xaa, 0x5c, 0x02, 0x31, 0x33, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x03, 0x8a, 0x68, 0x1f, 0xa5, 0x04, 0x01, 0x34, 0xa0, 0x5c, 0xb8, 0xc8, 0xae, 0x34, 0x15, 0x31, 0x68, 0xdf}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 0, // kSSLRead
				Data:     convertSliceToArray(event1Payload),
				DataLen:  int32(len(event1Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 2, // kRead
				Data:     convertSliceToArray(randomPayload),
				DataLen:  int32(len(randomPayload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 1, // kSSLWrite
				Data:     convertSliceToArray(event2Payload),
				DataLen:  int32(len(event2Payload)),
			})
		})

		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("http"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}
		})

		It("the first flow contains an HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).ToNot(BeNil())
			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("GET"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("1.1"))
			Expect(req.Host).To(Equal("localhost:4122"))

			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			Expect(flows[1].Response).ToNot(BeNil())

			resp, ok := flows[1].Response.(*sockets.HTTPResponse)
			Expect(ok).To(BeTrue())

			Expect(resp.Status).To(Equal(200))
			Expect(resp.HttpVersion).To(Equal("1.1"))
			Expect(resp.Headers["Content-Type"]).To(Equal([]string{"text/plain"}))
			Expect(resp.Headers["Content-Length"]).To(Equal([]string{"13"}))
			Expect(resp.Headers["Date"]).To(Equal([]string{"Fri, 15 Sep 2023 07:18:18 GMT"}))
			Expect(resp.Payload).To(Equal([]byte("Hello world.\n")))
		})
	})

	Context("Receiving Data (request), Data (response) events", Ordered, func() {
		var flows []*sockets.Flow
		payloads := [][]byte{
			event1Payload,
			event2Payload,
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 1, // TODO: Use the constant from bpf_events kSSLWrite
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("http"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}
		})

		It("the first flow contains an HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).ToNot(BeNil())
			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("GET"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("1.1"))
			Expect(req.Host).To(Equal("localhost:4122"))

			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			Expect(flows[1].Response).ToNot(BeNil())

			resp, ok := flows[1].Response.(*sockets.HTTPResponse)
			Expect(ok).To(BeTrue())

			Expect(resp.Status).To(Equal(200))
			Expect(resp.HttpVersion).To(Equal("1.1"))
			Expect(resp.Headers["Content-Type"]).To(Equal([]string{"text/plain"}))
			Expect(resp.Headers["Content-Length"]).To(Equal([]string{"13"}))
			Expect(resp.Headers["Date"]).To(Equal([]string{"Fri, 15 Sep 2023 07:18:18 GMT"}))
			Expect(resp.Payload).To(Equal([]byte("Hello world.\n")))
		})
	})

	Context("Receiving Data (request), Data (response) events (scenario 2)", Ordered, func() {
		var flows []*sockets.Flow

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 2, // kRead
				Data:     convertSliceToArray(event5Payload),
				DataLen:  int32(len(event5Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 3, // kWrite
				Data:     convertSliceToArray(event6Payload),
				DataLen:  int32(len(event6Payload)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 3, // kWrite
				Data:     convertSliceToArray(event13Payload),
				DataLen:  int32(len(event13Payload)),
			})
		})
		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("http"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}
		})

		It("the first flow contains an HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).ToNot(BeNil())
			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("GET"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("1.1"))
			Expect(req.Host).To(Equal("www.pntest.io"))

			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			Expect(flows[1].Response).ToNot(BeNil())

			resp, ok := flows[1].Response.(*sockets.HTTPResponse)
			Expect(ok).To(BeTrue())

			Expect(resp.Status).To(Equal(301))
			Expect(resp.HttpVersion).To(Equal("1.1"))
			Expect(resp.Headers["Content-Type"]).To(Equal([]string{"text/html"}))
			Expect(resp.Headers["Date"]).To(Equal([]string{"Sat, 04 Nov 2023 20:05:14 GMT"}))
			Expect(resp.Payload).To(Equal([]byte{}))
		})
	})

	Context("Receiving Data (request), Data (response) events (chunked) from Go", Ordered, func() {
		var flows []*sockets.Flow
		payloads := [][]byte{
			event8Payload,
			event9Payload,
			event10Payload,
			event11Payload,
			event12Payload,
			event13Payload,
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			// Request event
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 7, // goTlsWrite
				Data:     convertSliceToArray(event7Payload),
				DataLen:  int32(len(event7Payload)),
			})

			// Response events
			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 6, // goTlsRead
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("http"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}
		})

		It("the first flow contains an HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).ToNot(BeNil())
			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("GET"))
			Expect(req.Path).To(Equal("/chunked"))
			Expect(req.HttpVersion).To(Equal("1.1"))
			Expect(req.Host).To(Equal("localhost:4123"))

			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			// Expect(flows[1].Response).To(Equal(event7Payload)) // without the trailing zeroes

			// fmt.Println(string(flows[1].Response))
		})
	})

	Context("Receiving Data (request), Data (response) events (gzip'd)", Ordered, func() {
		var flows []*sockets.Flow

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			// Request event
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 7, // goTlsWrite
				Data:     convertSliceToArray(gzip1Payload),
				DataLen:  int32(len(gzip1Payload)),
			})

			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: 6, // goTlsRead
				Data:     convertSliceToArray(gzip2Payload),
				DataLen:  int32(len(gzip2Payload)),
			})
		})

		It("returns two flows", func() {
			Expect(flows).To(HaveLen(2))

			for _, flow := range flows {
				Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
				Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
				Expect(flow.L4Protocol).To(Equal("tcp"))
				Expect(flow.L7Protocol).To(Equal("http"))
				Expect(flow.PID).To(Equal(123))
				Expect(flow.FD).To(Equal(5))
			}
		})

		It("the first flow contains an HTTP request", func() {
			flow := flows[0]
			Expect(flow.Request).ToNot(BeNil())
			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("GET"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("1.1"))
			Expect(req.Host).To(Equal("www.example.com"))

			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP request and response", func() {
			Expect(flows[1].Request).To(BeNil())
			Expect(flows[1].Response).ToNot(BeNil())

			resp, ok := flows[1].Response.(*sockets.HTTPResponse)
			Expect(ok).To(BeTrue())

			Expect(resp.Status).To(Equal(200))
			Expect(resp.HttpVersion).To(Equal("1.1"))
			Expect(resp.Headers["Content-Type"]).To(Equal([]string{"text/html; charset=UTF-8"}))
			Expect(resp.Headers["Date"]).To(Equal([]string{"Mon, 12 Aug 2024 07:23:28 GMT"}))
			Expect(resp.Payload).To(Equal([]byte{60, 33, 100, 111, 99, 116, 121, 112, 101, 32, 104, 116, 109, 108, 62, 10, 60, 104, 116, 109, 108, 62, 10, 60, 104, 101, 97, 100, 62, 10, 32, 32, 32, 32, 60, 116, 105, 116, 108, 101, 62, 69, 120, 97, 109, 112, 108, 101, 32, 68, 111, 109, 97, 105, 110, 60, 47, 116, 105, 116, 108, 101, 62, 10, 10, 32, 32, 32, 32, 60, 109, 101, 116, 97, 32, 99, 104, 97, 114, 115, 101, 116, 61, 34, 117, 116, 102, 45, 56, 34, 32, 47, 62, 10, 32, 32, 32, 32, 60, 109, 101, 116, 97, 32, 104, 116, 116, 112, 45, 101, 113, 117, 105, 118, 61, 34, 67, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 34, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 34, 32, 47, 62, 10, 32, 32, 32, 32, 60, 109, 101, 116, 97, 32, 110, 97, 109, 101, 61, 34, 118, 105, 101, 119, 112, 111, 114, 116, 34, 32, 99, 111, 110, 116, 101, 110, 116, 61, 34, 119, 105, 100, 116, 104, 61, 100, 101, 118, 105, 99, 101, 45, 119, 105, 100, 116, 104, 44, 32, 105, 110, 105, 116, 105, 97, 108, 45, 115, 99, 97, 108, 101, 61, 49, 34, 32, 47, 62, 10, 32, 32, 32, 32, 60, 115, 116, 121, 108, 101, 32, 116, 121, 112, 101, 61, 34, 116, 101, 120, 116, 47, 99, 115, 115, 34, 62, 10, 32, 32, 32, 32, 98, 111, 100, 121, 32, 123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 98, 97, 99, 107, 103, 114, 111, 117, 110, 100, 45, 99, 111, 108, 111, 114, 58, 32, 35, 102, 48, 102, 48, 102, 50, 59, 10, 32, 32, 32, 32, 32, 32, 32, 32, 109, 97, 114, 103, 105, 110, 58, 32, 48, 59, 10, 32, 32, 32, 32, 32, 32, 32, 32, 112, 97, 100, 100, 105, 110, 103, 58, 32, 48, 59, 10, 32, 32, 32, 32, 32, 32, 32, 32, 102, 111, 110, 116, 45, 102, 97, 109, 105, 108, 121, 58, 32, 45, 97, 112, 112, 108, 101, 45, 115, 121, 115, 116, 101, 109, 44, 32, 115, 121, 115, 116, 101, 109, 45, 117, 105, 44, 32, 66, 108, 105, 110, 107, 77, 97, 99, 83, 121, 115, 116, 101, 109, 70, 111, 110, 116, 44, 32, 34, 83, 101, 103, 111, 101, 32, 85, 73, 34, 44, 32, 34, 79, 112, 101, 110, 32, 83, 97, 110, 115, 34, 44, 32, 34, 72, 101, 108, 118, 101, 116, 105, 99, 97, 32, 78, 101, 117, 101, 34, 44, 32, 72, 101, 108, 118, 101, 116, 105, 99, 97, 44, 32, 65, 114, 105, 97, 108, 44, 32, 115, 97, 110, 115, 45, 115, 101, 114, 105, 102, 59, 10, 32, 32, 32, 32, 32, 32, 32, 32, 10, 32, 32, 32, 32, 125, 10, 32, 32, 32, 32, 100, 105, 118, 32, 123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 119, 105, 100, 116, 104, 58, 32, 54, 48, 48, 112, 120, 59, 10, 32, 32, 32, 32, 32, 32, 32, 32, 109, 97, 114, 103, 105, 110, 58, 32, 53, 101, 109, 32, 97, 117, 116, 111, 59, 10, 32, 32, 32, 32, 32, 32, 32, 32, 112, 97, 100, 100, 105, 110, 103, 58, 32, 50, 101, 109, 59, 10, 32, 32, 32, 32, 32, 32, 32, 32, 98, 97, 99, 107, 103, 114, 111, 117, 110, 100, 45, 99, 111, 108, 111, 114, 58, 32, 35, 102, 100, 102, 100, 102, 102, 59, 10, 32, 32, 32, 32, 32, 32, 32, 32, 98, 111, 114, 100, 101, 114, 45, 114, 97, 100, 105, 117, 115, 58}))
		})
	})

	Context("Receiving POST request with body", Ordered, func() {
		var flows []*sockets.Flow

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: events.KRead,
				Data:     convertSliceToArray(post1Payload),
				DataLen:  int32(len(post1Payload)),
			})

		})

		It("returns a flow", func() {
			Expect(flows).To(HaveLen(1))

			flow := flows[0]
			Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
			Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))

			httpReq := flow.Request.(*sockets.HTTPRequest)
			Expect(httpReq.Method).To(Equal("POST"))
			Expect(httpReq.Host).To(Equal("megaserver:4122"))
			Expect(httpReq.Path).To(Equal("/"))
			Expect(httpReq.HttpVersion).To(Equal("1.1"))
			Expect(httpReq.Headers["User-Agent"]).To(ConsistOf([]string{"curl/8.12.1"}))
			Expect(httpReq.Headers["Accept"]).To(ConsistOf([]string{"*/*"}))
			Expect(httpReq.Headers["Content-Length"]).To(ConsistOf([]string{"19"}))
			Expect(httpReq.Headers["Content-Type"]).To(ConsistOf([]string{"application/x-www-form-urlencoded"}))
			Expect(string(httpReq.Payload)).To(Equal("!!!!!hellowrodl!!!!"))
		})
	})
})
