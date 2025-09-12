package sockets_test

import (
	"encoding/hex"
	"fmt"

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

			expected, _ := hexDumpToBytes(expectedHttp11Payload2)
			Expect(resp.Status).To(Equal(301))
			Expect(resp.HttpVersion).To(Equal("1.1"))
			Expect(resp.Headers["Content-Type"]).To(Equal([]string{"text/html"}))
			Expect(resp.Headers["Date"]).To(Equal([]string{"Sat, 04 Nov 2023 20:05:14 GMT"}))
			Expect(resp.Payload).To(Equal(expected))
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

			expected, _ := hexDumpToBytes(expectedHttp11Payload)
			Expect(resp.Status).To(Equal(200))
			Expect(resp.HttpVersion).To(Equal("1.1"))
			Expect(resp.Headers["Content-Type"]).To(Equal([]string{"text/html; charset=UTF-8"}))
			Expect(resp.Headers["Date"]).To(Equal([]string{"Mon, 12 Aug 2024 07:23:28 GMT"}))
			Expect(resp.Payload).To(Equal(expected))
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

	Context("Receiving Data (request), Data (response) events to https:/trayce.dev/robots.txt", Ordered, func() {
		var flows []*sockets.Flow

		// Request payload
		event1Bytes, _ := hexDumpToBytes(event16)
		// Response payload
		event2Bytes, _ := hexDumpToBytes(event17)
		event3Bytes, _ := hexDumpToBytes(event18)
		event4Bytes, _ := hexDumpToBytes(event19)

		BeforeAll(func() {
			socket := sockets.NewSocketHttp11("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: events.KSSLWrite,
				Data:     convertSliceToArray(event1Bytes),
				DataLen:  int32(len(event1Bytes)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: events.KSSLRead,
				Data:     convertSliceToArray(event2Bytes),
				DataLen:  int32(len(event2Bytes)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: events.KSSLRead,
				Data:     convertSliceToArray(event3Bytes),
				DataLen:  int32(len(event3Bytes)),
			})
			socket.ProcessDataEvent(&events.DataEvent{
				PID:      123,
				TID:      123,
				FD:       5,
				DataType: events.KSSLRead,
				Data:     convertSliceToArray(event4Bytes),
				DataLen:  int32(len(event4Bytes)),
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
			Expect(req.Path).To(Equal("/robots.txt"))
			Expect(req.HttpVersion).To(Equal("1.1"))
			Expect(req.Host).To(Equal("trayce.dev"))

			Expect(flow.Response).To(BeNil())
		})

		It("the second flow contains an HTTP response", func() {
			flow := flows[1]
			Expect(flow.Response).ToNot(BeNil())
			resp, ok := flow.Response.(*sockets.HTTPResponse)
			Expect(ok).To(BeTrue())

			Expect(resp.Status).To(Equal(404))
			Expect(resp.HttpVersion).To(Equal("1.1"))
			Expect(resp.Headers["Content-Type"]).To(Equal([]string{"text/html; charset=utf-8"}))
			Expect(len(resp.Payload)).ToNot(Equal(0))
			fmt.Println(hex.Dump(resp.Payload))
		})
	})
})
