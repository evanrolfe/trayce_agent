package sockets_test

import (
	"fmt"
	"strings"

	"github.com/evanrolfe/trayce_agent/internal/events"
	"github.com/evanrolfe/trayce_agent/internal/sockets"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SocketHTTP2", func() {
	Context("Receiving a Connect & Data events (POST request)", Ordered, func() {
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
			socket := sockets.NewSocketHttp2(&events.ConnectEvent{
				Pid:  123,
				Tid:  123,
				Fd:   5,
				Ip:   2130706433,
				Port: 80,
			})
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					Pid:      123,
					Tid:      123,
					Fd:       5,
					DataType: 1,
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(2))

			flow := flows[0]
			Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.Pid).To(Equal(123))
			Expect(flow.Fd).To(Equal(5))

			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			lines := strings.Split(string(flow.Request), "\r\n")
			Expect(lines[0]).To(Equal("POST / HTTP/2"))
			Expect(lines[1]).To(Equal("host: 172.17.0.3:4123"))
			Expect(lines[2]).To(Equal("user-agent: curl/7.81.0"))
			Expect(lines[3]).To(Equal("accept: */*"))
			Expect(lines[4]).To(Equal("content-type: application/json"))
			Expect(lines[5]).To(Equal("content-length: 34"))
			Expect(lines[7]).To(Equal(`{"key1":"value1", "key2":"value2"}`))
		})

		It("returns a response flow", func() {
			flow := flows[1]
			Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.Pid).To(Equal(123))
			Expect(flow.Fd).To(Equal(5))

			Expect(flow.Request).To(BeNil())
			Expect(flow.Response).ToNot(BeNil())

			lines := strings.Split(string(flow.Response), "\r\n")
			Expect(lines[0]).To(Equal("HTTP/2 200"))
			Expect(lines[1]).To(Equal("content-type: text/plain"))
			Expect(lines[2]).To(Equal("content-length: 13"))
			Expect(lines[3]).To(Equal("date: Mon, 06 May 2024 16:32:41 GMT"))
			Expect(lines[5]).To(Equal("Hello world.\n"))
		})
	})

	Context("Receiving a Connect & Data events (GET request)", Ordered, func() {
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
			socket := sockets.NewSocketHttp2(&events.ConnectEvent{
				Pid:  123,
				Tid:  123,
				Fd:   5,
				Ip:   2130706433,
				Port: 80,
			})
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					Pid:      123,
					Tid:      123,
					Fd:       5,
					DataType: 6, // go_tls_read
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(1))

			flow := flows[0]
			Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.Pid).To(Equal(123))
			Expect(flow.Fd).To(Equal(5))

			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			lines := strings.Split(string(flow.Request), "\r\n")
			Expect(lines[0]).To(Equal("GET / HTTP/2"))
			fmt.Print(lines)
		})
	})

	Context("Receiving a Connect & Data events (GET request) with a large response payload", Ordered, func() {
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
			socket := sockets.NewSocketHttp2(&events.ConnectEvent{
				Pid:  123,
				Tid:  123,
				Fd:   5,
				Ip:   2130706433,
				Port: 80,
			})
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			// Process request payloads
			for _, payload := range payloads {
				socket.ProcessDataEvent(&events.DataEvent{
					Pid:      123,
					Tid:      123,
					Fd:       5,
					DataType: 6, // go_tls_read
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}

			// Process response payloads
			for _, payload := range responsePayloads {
				socket.ProcessDataEvent(&events.DataEvent{
					Pid:      123,
					Tid:      123,
					Fd:       5,
					DataType: 7, // go_tls_write
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(2))

			flow := flows[0]
			Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.Pid).To(Equal(123))
			Expect(flow.Fd).To(Equal(5))

			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			lines := strings.Split(string(flow.Request), "\r\n")
			Expect(lines[0]).To(Equal("GET / HTTP/2"))
			fmt.Print(lines)
		})

		It("returns a response flow", func() {
			flow := flows[1]
			Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.Pid).To(Equal(123))
			Expect(flow.Fd).To(Equal(5))

			Expect(flow.Request).To(BeNil())
			// Expect(flow.Response).To(BeNil())

			// lines := strings.Split(string(flow.Request), "\r\n")
			// Expect(lines[0]).To(Equal("GET / HTTP/2"))
			// fmt.Print(lines)
		})
	})

	Context("Receiving a Connect & Data events (POST request) with a large request payload", Ordered, func() {
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
			socket := sockets.NewSocketHttp2(&events.ConnectEvent{
				Pid:  123,
				Tid:  123,
				Fd:   5,
				Ip:   2130706433,
				Port: 80,
			})
			socket.AddFlowCallback(func(flowFromCb sockets.Flow) {
				flows = append(flows, &flowFromCb)
			})

			// Process request payloads
			for _, payload := range requestPayloads {
				socket.ProcessDataEvent(&events.DataEvent{
					Pid:      123,
					Tid:      123,
					Fd:       5,
					DataType: 6, // go_tls_read
					Data:     convertSliceToArray(payload),
					DataLen:  int32(len(payload)),
				})
			}
		})

		It("returns a request flow", func() {
			Expect(flows).To(HaveLen(1))

			flow := flows[0]
			Expect(flow.RemoteAddr).To(Equal("127.0.0.1:80"))
			Expect(flow.L4Protocol).To(Equal("tcp"))
			Expect(flow.L7Protocol).To(Equal("http2"))
			Expect(flow.Pid).To(Equal(123))
			Expect(flow.Fd).To(Equal(5))

			Expect(flow.Request).ToNot(BeNil())
			Expect(flow.Response).To(BeNil())

			lines := strings.Split(string(flow.Request), "\r\n")
			Expect(lines[0]).To(Equal("POST / HTTP/2"))
			fmt.Print(lines)
		})
	})
})
