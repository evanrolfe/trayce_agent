package sockets_test

import (
	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/evanrolfe/trayce_agent/internal/sockets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SocketHTTP2", func() {
	Context("Receiving Data events (POST request)", Ordered, func() {
		flows := []*sockets.Flow{}

		// uprobe/go_tls_write
		// {0x00, 0x00, 0x1e, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x10, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xfa, 0x00, 0x06, 0x00, 0x10, 0x01, 0x40, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00},
		// uprobe/go_tls_read
		// {0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a},
		payloads := [][]byte{
			// uprobe/go_tls_read
			{0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x01, 0xff, 0x00, 0x01},
			{0x00, 0x00, 0x31, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01},
			{0x83, 0x84, 0x87, 0x41, 0x8b, 0x0b, 0xa2, 0x5c, 0x2e, 0xae, 0x05, 0xd9, 0xb8, 0xd0, 0x44, 0xcf, 0x7a, 0x88, 0x25, 0xb6, 0x50, 0xc3, 0xab, 0xbc, 0x15, 0xc1, 0x53, 0x03, 0x2a, 0x2f, 0x2a, 0x5f, 0x8b, 0x1d, 0x75, 0xd0, 0x62, 0x0d, 0x26, 0x3d, 0x4c, 0x74, 0x41, 0xea, 0x0f, 0x0d, 0x02, 0x33, 0x34},
			// uprobe/go_tls_write
			{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01},
			// uprobe/go_tls_read
			{0x00, 0x00, 0x22, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01},
			{0x7b, 0x22, 0x6b, 0x65, 0x79, 0x31, 0x22, 0x3a, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x31, 0x22, 0x2c, 0x20, 0x22, 0x6b, 0x65, 0x79, 0x32, 0x22, 0x3a, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x32, 0x22, 0x7d},
			{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00},
			// uprobe/go_tls_write
			{0x00, 0x00, 0x26, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x88, 0x5f, 0x87, 0x49, 0x7c, 0xa5, 0x8a, 0xe8, 0x19, 0xaa, 0x5c, 0x02, 0x31, 0x33, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x03, 0x8a, 0x68, 0x1f, 0xa5, 0x04, 0x01, 0x34, 0xa0, 0x5c, 0xb8, 0xc8, 0xae, 0x34, 0x15, 0x31, 0x68, 0xdf},
			{0x00, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e, 0x0a},
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp2("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 1,
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(2))

			flow := flows[0]
			Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
			Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))

			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("POST"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("2"))
			Expect(req.Host).To(Equal("172.17.0.3:4123"))
			Expect(req.Headers["user-agent"]).To(Equal([]string{"curl/7.81.0"}))
			Expect(req.Headers["accept"]).To(Equal([]string{"*/*"}))
			Expect(req.Headers["content-type"]).To(Equal([]string{"application/json"}))
			Expect(req.Headers["content-length"]).To(Equal([]string{"34"}))
			Expect(req.Payload).To(Equal([]byte(`{"key1":"value1", "key2":"value2"}`)))
		})

		It("returns a response flow", func() {
			flow := flows[1]
			Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
			Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))

			Expect(flow.Request).To(BeNil())
			Expect(flow.Response).ToNot(BeNil())

			resp, ok := flow.Response.(*sockets.HTTPResponse)
			Expect(ok).To(BeTrue())

			Expect(resp.Status).To(Equal(200))
			Expect(resp.HttpVersion).To(Equal("2"))
			Expect(resp.Headers["content-type"]).To(Equal([]string{"text/plain"}))
			Expect(resp.Headers["content-length"]).To(Equal([]string{"13"}))
			Expect(resp.Headers["date"]).To(Equal([]string{"Mon, 06 May 2024 16:32:41 GMT"}))
			Expect(resp.Payload).To(Equal([]byte("Hello world.\n")))
		})
	})

	Context("Receiving Data events (GET request)", Ordered, func() {
		flows := []*sockets.Flow{}

		payloads := [][]byte{
			{0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32, 0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A},
			{0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x01, 0xFF, 0x00, 0x01},
			{0x00, 0x00, 0x1F, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01},
			{0x82, 0x84, 0x87, 0x41, 0x8B, 0x0B, 0xA2, 0x5C, 0x2E, 0xAE, 0x05, 0xD9, 0xB8, 0xD0, 0x44, 0xCF, 0x7A, 0x88, 0x25, 0xB6, 0x50, 0xC3, 0xAB, 0xBC, 0x15, 0xC1, 0x53, 0x03, 0x2A, 0x2F, 0x2A},
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp2("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 6, // go_tls_read
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(1))

			flow := flows[0]
			Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
			Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))

			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("GET"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("2"))
			Expect(req.Host).To(Equal("172.17.0.3:4123"))
			Expect(req.Headers["user-agent"]).To(Equal([]string{"curl/7.81.0"}))
			Expect(req.Headers["accept"]).To(Equal([]string{"*/*"}))
		})
	})

	Context("Receiving Data events (GET request) with a large response payload", Ordered, func() {
		flows := []*sockets.Flow{}

		// Request payloads
		payloads := [][]byte{
			{0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32, 0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A},
			{0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x01, 0xFF, 0x00, 0x01},
			{0x00, 0x00, 0x1F, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01},
			{0x82, 0x84, 0x87, 0x41, 0x8B, 0x0B, 0xA2, 0x5C, 0x2E, 0xAE, 0x05, 0xD9, 0xB8, 0xD0, 0x44, 0xCF, 0x7A, 0x88, 0x25, 0xB6, 0x50, 0xC3, 0xAB, 0xBC, 0x15, 0xC1, 0x53, 0x03, 0x2A, 0x2F, 0x2A},
		}

		// Response payloads
		event1Payload, _ := hexDumpToBytes(http2Event1)
		event2Payload, _ := hexDumpToBytes(http2Event2)
		event3Payload, _ := hexDumpToBytes(http2Event3)
		event4Payload, _ := hexDumpToBytes(http2Event4)

		responsePayloads := [][]byte{
			event1Payload,
			event2Payload,
			event3Payload,
			event4Payload,
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp2("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			// Process request payloads
			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 6, // go_tls_read
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}

			// Process response payloads
			for _, payload := range responsePayloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 7, // go_tls_write
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(2))

			flow := flows[0]
			Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
			Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))

			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("GET"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("2"))
			Expect(req.Host).To(Equal("172.17.0.3:4123"))
			Expect(req.Headers["user-agent"]).To(Equal([]string{"curl/7.81.0"}))
			Expect(req.Headers["accept"]).To(Equal([]string{"*/*"}))
		})

		It("returns a response flow", func() {
			flow := flows[1]
			Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
			Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))

			Expect(flow.Request).To(BeNil())
			Expect(flow.Response).ToNot(BeNil())

			resp, ok := flow.Response.(*sockets.HTTPResponse)
			Expect(ok).To(BeTrue())

			Expect(resp.Status).To(Equal(200))
			Expect(resp.HttpVersion).To(Equal("2"))
			Expect(resp.Headers["content-type"]).To(Equal([]string{"text/plain"}))
			Expect(resp.Headers["date"]).To(Equal([]string{"Mon, 03 Jun 2024 08:16:38 GMT"}))
			Expect(len(resp.Payload)).To(Equal(4891))
		})
	})

	Context("Receiving Data events (POST request) with a large request payload", Ordered, func() {
		flows := []*sockets.Flow{}

		// Request payloads
		event5Payload, _ := hexDumpToBytes(http2Event5)
		event6Payload, _ := hexDumpToBytes(http2Event6)
		event7Payload, _ := hexDumpToBytes(http2Event7)
		event8Payload, _ := hexDumpToBytes(http2Event8)
		event9Payload, _ := hexDumpToBytes(http2Event9)
		event10Payload, _ := hexDumpToBytes(http2Event10)
		event11Payload, _ := hexDumpToBytes(http2Event11)
		event12Payload, _ := hexDumpToBytes(http2Event12)
		event13Payload, _ := hexDumpToBytes(http2Event13)
		event14Payload, _ := hexDumpToBytes(http2Event14)

		requestPayloads := [][]byte{
			event5Payload,
			event6Payload,
			event7Payload,
			event8Payload,
			event9Payload,
			event10Payload,
			event11Payload,
			event12Payload,
			event13Payload,
			event14Payload,
		}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp2("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			// Process request payloads
			for _, payload := range requestPayloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 6, // go_tls_read
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(1))

			flow := flows[0]
			Expect(flow.SourceAddr).To(Equal("172.17.0.2:1234"))
			Expect(flow.DestAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.PID).To(Equal(123))
			Expect(flow.FD).To(Equal(5))

			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			req, ok := flow.Request.(*sockets.HTTPRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Method).To(Equal("POST"))
			Expect(req.Path).To(Equal("/"))
			Expect(req.HttpVersion).To(Equal("2"))
			Expect(req.Host).To(Equal("172.17.0.3:4123"))
			Expect(req.Headers["user-agent"]).To(Equal([]string{"curl/7.81.0"}))
			Expect(req.Headers["accept"]).To(Equal([]string{"*/*"}))
			Expect(req.Headers["content-type"]).To(Equal([]string{"application/x-www-form-urlencoded"}))
			Expect(req.Headers["content-length"]).To(Equal([]string{"4889"}))
			Expect(len(req.Payload)).To(Equal(4889))
		})
	})

	// Weird egdge case here, http2Event23 is actually two HTTP2 frames combined into one event, for some reason Go occasionally
	// sends bytes over like that (like < 5% of the time), so annoyingly we have to handle this
	//
	// http2Event23 payload below combines a Settings frame (type 0x04) and a Window Update frame (type 0x08)
	// 00 00 00 04 01 00 00 00  00 00 00 04 08 00 00 00
	// 00 00 00 0f 00 01
	//
	// First Frame:
	// 00 00 00 04 01 00 00 00 00
	//
	// Length: 				00 00 00 (0 bytes)
	// Type: 				04 (Settings frame)
	// Flags: 				01 (ACK flag set)
	// Reserved: 			0 (part of the Stream Identifier)
	// Stream Identifier: 	00 00 00 00 (Stream 0)
	//
	// This is an ACK Settings frame with no payload.
	// Total length: 9 bytes (frame header only)
	//
	// Second Frame:
	// 00 00 04 08 00 00 00 00 00 00 00 0f 00 01
	//
	// Length: 				00 00 04 (4 bytes)
	// Type: 				08 (Window Update frame)
	// Flags: 				00 (no flags set)
	// Reserved: 			0 (part of the Stream Identifier)
	// Stream Identifier: 	00 00 00 00 (Stream 0)
	// Payload: 			00 00 00 0f (Window size increment of 15)
	//
	// This is a Window Update frame with a payload length of 4 bytes.
	// Total length: 13 bytes (9 bytes header + 4 bytes payload)
	//
	Context("Receiving Data events (GET request), then Data events with a multiple response frames in one event", Ordered, func() {
		flows := []*sockets.Flow{}

		// Request payloads
		http2Event15, _ := hexDumpToBytes(http2Event15)
		http2Event16, _ := hexDumpToBytes(http2Event16)
		http2Event17, _ := hexDumpToBytes(http2Event17)
		http2Event18, _ := hexDumpToBytes(http2Event18)
		http2Event19, _ := hexDumpToBytes(http2Event19)
		http2Event20, _ := hexDumpToBytes(http2Event20)
		http2Event21, _ := hexDumpToBytes(http2Event21)
		http2Event22, _ := hexDumpToBytes(http2Event22)
		http2Event23, _ := hexDumpToBytes(http2Event23)
		http2Event24, _ := hexDumpToBytes(http2Event24)

		requestPayloads := [][]byte{
			http2Event15,
			http2Event16,
			http2Event17,
			http2Event18,
			http2Event19,
			http2Event20,
			http2Event21,
		}
		responsePayloads := [][]byte{http2Event22, http2Event23, http2Event24}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp2("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			// Process request payloads
			for _, payload := range requestPayloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 6, // go_tls_read
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
			// Process response payloads
			for _, payload := range responsePayloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 7, // go_tls_write
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(2))

			Expect(flows[0].Request).ToNot(BeNil())
			Expect(flows[0].Response).To(BeNil())

			Expect(flows[1].Request).To(BeNil())
			Expect(flows[1].Response).ToNot(BeNil())

			// lines := strings.Split(string(flow.Request.GetData()), "\r\n")
			// Expect(lines[0]).To(Equal("POST / HTTP/2"))
			// fmt.Print(lines)
		})
	})

	Context("Receiving Data events (GRPC messages)", Ordered, func() {
		flows := []*sockets.Flow{}

		// Request payloads
		grpcEvent1Bytes, _ := hexDumpToBytes(grpcEvent1)
		grpcEvent2Bytes, _ := hexDumpToBytes(grpcEvent2)
		grpcEvent3Bytes, _ := hexDumpToBytes(grpcEvent3)
		grpcEvent4Bytes, _ := hexDumpToBytes(grpcEvent4)

		requestPayloads := [][]byte{grpcEvent1Bytes, grpcEvent2Bytes}
		responsePayloads := [][]byte{grpcEvent3Bytes, grpcEvent4Bytes}

		BeforeAll(func() {
			socket := sockets.NewSocketHttp2("172.17.0.2:1234", "127.0.0.1:80", 123, 123, 5)
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			// Process request payloads
			for _, payload := range requestPayloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 6, // go_tls_read
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
			// Process response payloads
			for _, payload := range responsePayloads {
				socket.ProcessDataEvent(&events.DataEvent{
					PID:      123,
					TID:      123,
					FD:       5,
					DataType: 7, // go_tls_write
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(2))
			flow := flows[0]

			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("grpc"))

			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			req, ok := flow.Request.(*sockets.GRPCRequest)
			Expect(ok).To(BeTrue())

			Expect(req.Path).To(Equal("/api.TrayceAgent/SendContainersObserved"))
			Expect(req.Headers["user-agent"]).To(Equal([]string{"grpc-go/1.65.0"}))
			Expect(req.Headers["te"]).To(Equal([]string{"trailers"}))
			Expect(req.Headers["content-type"]).To(Equal([]string{"application/grpc"}))
			Expect(req.Payload).To(Equal([]byte{0, 0, 0, 0, 43, 10, 41, 10, 4, 49, 50, 51, 52, 18, 6, 117, 98, 117, 110, 116, 117, 26, 10, 49, 55, 50, 46, 48, 46, 49, 46, 49, 57, 34, 4, 101, 118, 97, 110, 42, 7, 114, 117, 110, 110, 105, 110, 103}))
		})

		It("returns a response flow", func() {
			Expect(flows).To(HaveLen(2))
			flow := flows[1]

			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("grpc"))

			Expect(flow.Request).To(BeNil())
			Expect(flow.Response).ToNot(BeNil())

			resp, ok := flow.Response.(*sockets.GRPCResponse)
			Expect(ok).To(BeTrue())

			Expect(resp.Headers["content-type"]).To(Equal([]string{"application/grpc"}))
			Expect(resp.Payload).To(Equal([]byte{0, 0, 0, 0, 10, 10, 8, 115, 117, 99, 99, 101, 115, 115, 32}))
		})
	})
})
